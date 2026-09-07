#ifndef S3SEAL_PROXY_H
#define S3SEAL_PROXY_H

/**
 * Talking to the S3 behind us.
 *
 * Every call here is `meta_fetch` with `s3seal_sign` on it, and the point of
 * the file is that there is exactly one place that knows the upstream's
 * credentials, the URL shape and the metadata names.
 *
 * ------------------------------------------------------ what is stored, where
 *
 * All of it on the upstream, in the object's own user metadata:
 *
 *   x-amz-meta-seal    the wrapped data key, hex
 *   x-amz-meta-nonce   the four random bytes in front of every nonce, hex
 *   x-amz-meta-plain   the plaintext length, decimal
 *   x-amz-meta-part    the plaintext each part holds, or 0 for a single PUT
 *   x-amz-meta-etag    the plaintext ETag, which S3 will not let us set
 *
 * Under two kilobytes together, which is S3's ceiling for user metadata, and
 * settable at `CreateMultipartUpload` as well as at `PutObject` - which is
 * what makes the whole design work without a database.
 *
 * `plain` is written even though `s3seal_plainSize` can work it out from the
 * stored length. The arithmetic is what a *listing* uses, where there is no
 * metadata to read; here there is, and a number that was written down beats
 * one that was derived when the two can be compared.
 */

#include "config.h"
#include "frame.h"
#include "sign.h"

#include <meta_fetch.h>

typedef struct s3seal_proxy_t {
  s3seal_config_t *config;
  s3seal_master_t *master;
  s3seal_signer_t signer;
} s3seal_proxy_t;

void s3seal_proxy_t.start(s3seal_proxy_t *self, s3seal_config_t *config,
                          s3seal_master_t *master);

/**
 * Waits for every upstream push still in flight.
 *
 * The scope they run in is declared in proxy.c, so this is where it can be
 * joined - a worker that goes while one is half sent leaves an object the
 * upstream will never finish.
 */
void s3seal_proxy_t.stop(s3seal_proxy_t *self);

/** What we know about one stored object, out of its metadata. */
typedef struct s3seal_seal_t {
  unsigned char key[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];

  s3seal_layout_t how;

  char etag[S3SEAL_ETAG_MAX];
  char mime[128];
  char when[64];

  /** What the upstream holds, which is the plaintext plus the framing. */
  unsigned long long stored;

  /** Set when the object carries no sealing metadata - somebody else's. */
  int plain;
} s3seal_seal_t;

/**
 * Reads an object's metadata without its body.
 *
 * `plain` comes back set for an object that was in the bucket before this
 * proxy was, which is a case worth answering rather than failing on: the
 * honest thing is to pass it through untouched and say so.
 */
int s3seal_proxy_t.headOf(s3seal_proxy_t *self, const char *bucket,
                          const char *key, s3seal_seal_t *into, int *status);

/** Seals `body` and stores it. `etag` comes back as the plaintext MD5. */
int s3seal_proxy_t.put(s3seal_proxy_t *self, const char *bucket,
                       const char *key, const char *mime, const void *body,
                       size_t length, char *etag, size_t room);

/**
 * Fetches a plaintext range and opens it into `sink`.
 *
 * Whole frames are fetched and the ends are trimmed here, so the sink sees
 * exactly the bytes that were asked for and nothing before or after them.
 */
int s3seal_proxy_t.get(s3seal_proxy_t *self, const char *bucket,
                       const char *key, const s3seal_seal_t *what,
                       unsigned long long at, unsigned long long want,
                       fetch_sink_t sink, void *with);

/* --------------------------------------------------- pushing while receiving

 * The shape that makes a proxy cost what the upstream costs.
 *
 * `put` above takes a body that is already whole, which means receiving,
 * hashing and sending happen one after another - measured at 89, 62 and 155
 * milliseconds on 64 MB, against 150 for the same bytes straight to the
 * upstream. Three phases in series is why a proxy runs at half speed, and it
 * is not the encryption: sealing costs about five of those milliseconds and
 * already happens inside the sending.
 *
 * This is the same work overlapped. A piece arrives, is sealed, and goes at
 * the upstream while the next one is still on the wire. Nothing is held but a
 * frame.
 *
 * It needs the ETag to not be the plaintext's MD5 - see `opaqueEtag` in
 * config.h - because a metadata header cannot be known before the body it
 * describes.
 *
 * The upstream request runs on a thread of its own, reading from a pipe this
 * fills. A thread rather than a task for the reason the read path has one: a
 * green task filling a pipe that only its own carrier could drain is a
 * deadlock by construction. The writing end is non-blocking and parks on
 * `meta_writable`, so the carrier is given back whenever the pipe is full.
 */

typedef struct s3seal_push_t {
  s3seal_proxy_t *proxy;

  char bucket[S3SEAL_BUCKET_MAX + 1];
  char key[S3SEAL_KEY_MAX + 1];
  char mime[128];
  char url[S3SEAL_URL_MAX];

  unsigned char dataKey[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];

  /** What the client said it would send, which is what the framing needs. */
  unsigned long long plain;
  unsigned long long framed;
  unsigned long long frames;

  /** One frame of plaintext being gathered, and its sealed form. */
  unsigned char gathering[S3SEAL_FRAME];
  size_t fill;
  unsigned char out[S3SEAL_FRAME + S3SEAL_OVERHEAD + 32];
  size_t ready;
  size_t sent;
  int ended;

  unsigned long long number;
  unsigned long long crc;

  /** How many times the host handed something over, for the timing line. */
  unsigned long long pieces;

  /**
   * Where the streaming loop's time went, in milliseconds.
   *
   * Measured because a 64 MB run said the loop was fine and a 10 GB run said
   * it was half the upstream's speed. Fixed costs hid it; at ten gigabytes
   * there is nothing left to hide behind, so the three things the loop does
   * are timed separately rather than argued about.
   */
  double waited;
  double sealing;
  unsigned long long parks;

  /**
   * Three stages, two pipes.
   *
   *   the request task   plaintext  ->  intoPlain
   *   the sealing thread  fromPlain ->  intoSealed
   *   the sending thread              fromSealed -> curl -> the upstream
   *
   * The middle one exists because the sealing is 7 of the 20 seconds a ten
   * gigabyte upload takes, and while it runs on the task that receives,
   * nothing is being read from the host. A thread of its own is allowed to
   * block on a pipe - nobody is standing in its callback waiting - which is
   * what the first attempt at this got wrong.
   */
  int intoPlain;
  int fromPlain;
  int intoSealed;
  int fromSealed;

  int toldRead;
  int toldWrite;

  /** The headers the thread will send, built before it starts. */
  char out2[S3SEAL_BLOB * 2 + 1];
  char out3[S3SEAL_NONCE_PREFIX * 2 + 1];
  char out4[32];
  char out5[32];

  int status;
  char etag[S3SEAL_ETAG_MAX];

  int broke;
} s3seal_push_t;

/** Starts the upstream request and the thread that feeds it. */
int s3seal_proxy_t.pushBegin(s3seal_proxy_t *self, const char *bucket,
                             const char *key, const char *mime,
                             unsigned long long length, s3seal_push_t **into);

/** One piece of plaintext, as it arrived. Non-zero stops the read. */
int s3seal_pushPiece(void *with, const void *bytes, size_t length);

/** Finishes the body, waits for the upstream, and answers its ETag. */
int s3seal_push_t.end(s3seal_push_t *self, char *etag, size_t room);

/* ------------------------------------------------------------- multipart */

/**
 * An upload in progress, kept where a proxy is allowed to keep things.
 *
 * The wrapped key and the nonce go into the metadata of one tiny object
 * under the scratch prefix, written by `begin` and read by every `part` and
 * by `finish`. Nothing is held in this process, so a worker that restarts
 * mid-upload loses nothing and a second worker could serve the next part.
 */
typedef struct s3seal_upload_t {
  char bucket[S3SEAL_BUCKET_MAX + 1];
  char key[S3SEAL_KEY_MAX + 1];
  char mime[128];

  unsigned char dataKey[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
} s3seal_upload_t;

/** Makes an id and parks the key under it. */
int s3seal_proxy_t.begin(s3seal_proxy_t *self, const char *bucket,
                         const char *key, const char *mime, char *id,
                         size_t room);

/**
 * Reads it back.
 *
 * The bucket is a parameter and not remembered, because there is nowhere
 * safe to remember it: this struct is one per process and two requests for
 * two buckets would take turns overwriting a field. S3 hands the bucket in
 * on every multipart call anyway, so nothing is lost by asking for it.
 */
int s3seal_proxy_t.upload(s3seal_proxy_t *self, const char *bucket,
                          const char *id, s3seal_upload_t *into);

/**
 * Seals one part and parks it beside the others.
 *
 * The part's plaintext length and MD5 go in its *name*, so the completion
 * learns both from a single listing rather than from a HEAD of every part.
 * `etag` comes back as that MD5, which is what the part's ETag has to be.
 */
int s3seal_proxy_t.part(s3seal_proxy_t *self, const char *id,
                        const s3seal_upload_t *what, int number,
                        const void *body, size_t length, char *etag,
                        size_t room);

/**
 * Assembles the parked parts into the real object, server side.
 *
 * `UploadPartCopy`, so no byte comes back through this process. And the
 * upstream multipart upload is *ours*, created here - which is the whole
 * trick: its metadata is set at a moment when every part's MD5 is known, so
 * the object carries the right plaintext ETag from the start.
 */
int s3seal_proxy_t.finish(s3seal_proxy_t *self, const char *id,
                          const s3seal_upload_t *what, char *etag,
                          size_t room);

/** Drops the parked parts. */
void s3seal_proxy_t.abort(s3seal_proxy_t *self, const char *bucket,
                          const char *id);

/** Straight through, for the calls that carry no body of ours. */
int s3seal_proxy_t.pass(s3seal_proxy_t *self, const char *method,
                        const char *bucket, const char *key,
                        const char *query, fetch_answer_t *into);

#endif /* S3SEAL_PROXY_H */
