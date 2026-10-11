/**
 * The handlers.
 *
 * Two signatures per request and they are not the same one: the client's is
 * checked against our credentials file, and a fresh one is taken over the
 * request we make with the upstream's key. Nothing is forwarded verbatim.
 */
#include "s3.h"

#include "config.h"
#include "frame.h"
#include "proxy.h"
#include "sigv4.h"
#include "util.h"

#include <meta_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * A reader has a thread of its own, and it is not an optimisation.
 *
 * The answer to a GET is a pipe: this fills it, nginx drains it. A green task
 * doing the filling would be running on the very carrier that has to do the
 * draining, so a body larger than the pipe buffer would wait for a reader
 * that cannot run until the writer stops. That is a deadlock by construction
 * rather than a risk, and `go @thread` is what asks for the other kind.
 *
 * It also means the object is never whole anywhere: `s3seal_proxy_t.get`
 * opens one frame at a time and this writes each one out as it appears.
 */
task readers;

/**
 * Where a small answer is built.
 *
 * Thread-local and safe *because nothing parks between filling it and
 * returning it*: an error document and a rewritten listing are both built
 * from bytes already in hand. The GET path is the one that parks, and it
 * answers with a pipe rather than with this.
 */
static __thread s3seal_buf_t s3seal_answer;

static s3seal_config_t s3seal_settings;
static s3seal_master_t s3seal_master;
static s3seal_proxy_t s3seal_upstream;
static int s3seal_serving;

/**
 * A reply, in S3's own error shape.
 *
 * Clients read this. `aws s3 cp` prints the `Code` and rclone decides whether
 * to retry on it, so getting the words right is not decoration.
 */
static http_response_t problem(http_request_t *req, int status,
                               const char *code, const char *why) {

  s3seal_buf_t *out = &s3seal_answer;

  out->count = 0;
  out->broke = 0;

  out->add("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>");
  out->addXml(code);
  out->add("</Code><Message>");
  out->addXml(why);
  out->add("</Message></Error>");

  return req.reply(status).bytes("application/xml", out->at, out->count);
}

/**
 * Text that outlives the handler's frame.
 *
 * `http_response_t.header` keeps the *pointer* it is given, and the response
 * is written after the handler has returned - so a header naming a local
 * array is a header naming somebody else's stack by the time it is sent. It
 * showed up as an ETag of thirty random bytes.
 *
 * `req->scratch` is per request and lives exactly as long as the request,
 * which is the lifetime a header needs. Not a thread-local: a task that parks
 * on the upstream gives its carrier to another request, and two of them would
 * then share one buffer.
 */
static const char *heldText(http_request_t *req, text_t text) {

  char *into = req->scratch + req->scratchUsed;
  size_t room = (size_t)(META_HTTP_SCRATCH - req->scratchUsed);
  size_t length = text.into(into, room);

  if (length + 1 > room)
    return "";

  req->scratchUsed += (int)length + 1;

  return into;
}

static const char *held(http_request_t *req, const char *text) {
  return heldText(req, TEXT`${text}`);
}

/** The key a `*key` pattern caught, percent-decoded. */
static const char *keyOf(http_request_t *req, char *into, size_t room) {

  s3seal_unescape(req.param("key"), into, room);

  return into;
}

/* ------------------------------------------------------------ the doorman */

static http_response_t guard(http_request_t *req) {

  char who[128];
  enum s3sealAuth said;

  if (!s3seal_serving)
    return problem(req, 503, "ServiceUnavailable", "still starting up");

  said = s3seal_verify(&s3seal_settings, req, who, sizeof who);

  if (said == S3SEAL_AUTH_OK)
    return req.reply(0);

  switch (said) {
  case S3SEAL_AUTH_MISSING:
    return problem(req, 403, "AccessDenied", "this request is not signed");
  case S3SEAL_AUTH_UNKNOWN_KEY:
    return problem(req, 403, "InvalidAccessKeyId", "no such access key");
  case S3SEAL_AUTH_BAD_SIGNATURE:
    return problem(req, 403, "SignatureDoesNotMatch",
                   "the signature does not match");
  case S3SEAL_AUTH_SKEWED:
    return problem(req, 403, "RequestTimeTooSkewed",
                   "the request date is too far from ours");
  case S3SEAL_AUTH_MALFORMED:
    return problem(req, 400, "AuthorizationHeaderMalformed",
                   "the authorization header cannot be read");
  case S3SEAL_AUTH_OK:
    break;
  }

  return problem(req, 403, "AccessDenied", "no");
}

/* ---------------------------------------------------------------- objects */

static http_response_t uploadPart(http_request_t *req);
static http_response_t abortUpload(http_request_t *req);
static http_response_t onPut(http_request_t *req);
static int asked(http_request_t *req, const char *name);

static double s3seal_now_ms(void) {

  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);

  return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
}

/**
 * A PUT that never holds the object.
 *
 * Taken when the ETag is opaque and the host can hand a body over in pieces,
 * because those are the two things that let receiving and sending overlap:
 * nothing in the upstream's headers depends on bytes that have not arrived,
 * so the request can start on the first piece.
 *
 * `aws-chunked` framing needs the length up front, and the client's own
 * `Content-Length` is where it comes from - a chunked client request has no
 * length to give, so that one falls back to the buffered path.
 */
static http_response_t streamObject(http_request_t *req, const char *bucket,
                                    const char *key) {

  const char *said = req.header("content-length");
  unsigned long long length = said != NULL ? strtoull(said, NULL, 10) : 0;
  char etag[S3SEAL_ETAG_MAX];
  s3seal_push_t *how;
  int worst;

  if (said == NULL || said[0] == 0)
    return problem(req, 411, "MissingContentLength",
                   "a streamed upload has to say how long it is");

  {
    double began = s3seal_now_ms();
    double afterBegin;
    double afterBody;
    double afterEnd;
    unsigned long long pieces;
    unsigned long long parks;
    double waited;
    double sealRead;
    double sealWork;
    double sealWrite;
    int ended;

    if (s3seal_upstream.pushBegin(bucket, key, req.header("content-type"),
                                  length, &how) != 0)
      return problem(req, 502, "InternalError",
                     "the upload could not be begun");

    afterBegin = s3seal_now_ms();

    worst = req.streamBody(s3seal_pushPiece, how);

    afterBody = s3seal_now_ms();
    pieces = how->pieces;
    waited = how->waited;
    parks = how->parks;
    sealRead = how->sealRead;
    sealWork = how->sealWork;
    sealWrite = how->sealWrite;

    ended = how->end(etag, sizeof etag);

    afterEnd = s3seal_now_ms();

    if (getenv("S3SEAL_TIMING") != NULL)
      fprintf(stderr,
              "s3seal: %llu bytes - begin %.0f ms, stream %.0f ms in %llu "
              "piece(s) [parked %.0f in %llu; sealer: read %.0f, work %.0f, "
              "write %.0f], finish %.0f ms, total %.0f ms\n",
              length, afterBegin - began, afterBody - afterBegin, pieces,
              waited, parks, sealRead, sealWork, sealWrite,
              afterEnd - afterBody, afterEnd - began);

    if (ended != 0 || worst < 0)
      return problem(req, 502, "InternalError",
                     "the upstream would not take it");
  }

  return req.reply(200).header("ETag", held(req, etag)).send();
}

static http_response_t putObject(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  char etag[S3SEAL_ETAG_MAX];
  const char *bucket = req.param("bucket");
  double began;
  http_body_t body;
  double afterBody;

  /**
   * The overlapping path first, because the buffered one begins by waiting
   * for the whole body and there is no going back from that.
   */
  if (s3seal_settings.opaqueEtag && req.canStream()) {

    char early[S3SEAL_KEY_MAX + 1];
    const char *encoding = req.header("content-encoding");

    keyOf(req, early, sizeof early);

    if (s3seal_settings.ours(early))
      return problem(req, 403, "AccessDenied", "that prefix is the proxy's");

    /* aws-chunked from the client has to be unwrapped first, and unwrapping
       is something the buffered path does */
    if (encoding == NULL || strstr(encoding, "aws-chunked") == NULL)
      return streamObject(req, bucket, early);
  }

  began = s3seal_now_ms();
  body = req.readBody();
  afterBody = s3seal_now_ms();

  keyOf(req, key, sizeof key);

  if (s3seal_settings.ours(key))
    return problem(req, 403, "AccessDenied", "that prefix is the proxy's");

  if (body.length > s3seal_settings.maxPart)
    return problem(req, 413, "EntityTooLarge",
                   "use a multipart upload for something this size");

  /**
   * `aws-chunked` framing comes off before anything else looks at the body -
   * but only when the client said it used it.
   *
   * `content-encoding` is what says so, and asking is not optional: taking
   * every body for a framed one turns an ordinary PUT into a parse error,
   * which is exactly what the first run of this did.
   */
  {
    const char *encoding = req.header("content-encoding");

    if (encoding != NULL && strstr(encoding, "aws-chunked") != NULL) {

      int worst, size_t length =
          s3seal_dechunk((char *)body.bytes, body.length);

      if (worst != 0)
        return problem(req, 400, "MalformedChunkedBody", "bad chunk framing");

      body.length = length;
    }
  }

  if (getenv("S3SEAL_TIMING") != NULL)
    fprintf(stderr, "s3seal: nginx took %.0f ms to hand over %llu bytes\n",
            afterBody - began, (unsigned long long)body.length);

  if (s3seal_upstream.put(bucket, key, req.header("content-type"), body.bytes,
                          body.length, etag, sizeof etag) != 0)
    return problem(req, 502, "InternalError", "the upstream would not take it");

  return req.reply(200).header("ETag", held(req, etag)).send();
}

/** What a reader thread was told to fetch. Its own, and it frees it. */
typedef struct {
  char bucket[S3SEAL_BUCKET_MAX + 1];
  char key[S3SEAL_KEY_MAX + 1];

  s3seal_seal_t what;

  unsigned long long at;
  unsigned long long want;

  int into;

  /** Set for a whole read, which asks once and learns as it goes. */
  int whole;
  s3seal_learn_t learn;
  int tell;
} s3seal_pull_t;

/**
 * Opened bytes into the pipe nginx is streaming from.
 *
 * `EINTR` is not a failure and must not be reported as one. A short return
 * from this is how curl is told the application could not take the data, and
 * it answers by aborting the transfer with CURLE_WRITE_ERROR - so a signal
 * arriving while a worker sat in `write` used to end the download, leave the
 * body short of the Content-Length already sent, and hang the client until it
 * gave up. Measured at eight concurrent clients: 23 aborted reads in twenty
 * seconds, every one of them "Failed writing received data to disk".
 */
static size_t intoPipe(void *with, const void *bytes, size_t length) {

  const char *at = bytes;
  size_t done = 0;

  while (done < length) {

    ssize_t put = write(*(int *)with, at + done, length - done);

    if (put < 0 && errno == EINTR)
      continue;

    if (put <= 0)
      return done;

    done += (size_t)put;
  }

  return done;
}

static void pullRun(s3seal_pull_t *job) {

  if (job->whole) {

    job->learn.bucket = job->bucket;
    job->learn.key = job->key;
    job->learn.tell = job->tell;

    s3seal_upstream.getWhole(&job->learn, intoPipe, &job->into);

    /**
     * The request task is parked on `tell` and has to be let go even when no
     * headers ever came - a 404 or a refused connection reaches no hook, and
     * a task parked on a pipe nobody will write to never answers.
     */
    if (!job->learn.told) {

      unsigned char one = 1;

      job->learn.told = 1;
      (void)!write(job->tell, &one, 1);
    }

    close(job->tell);

  } else {

    s3seal_upstream.get(job->bucket, job->key, &job->what, job->at, job->want,
                        intoPipe, &job->into);
  }

  /* the close is what tells nginx the answer is finished, whether it went
     well or not - a client sees a short body, which is what a failed read of
     an already-started response can be */
  close(job->into);

  free(job);
}

/**
 * A whole object, in one request to the upstream.
 *
 * The order is the awkward part. A client has to be told Content-Length
 * before the body starts, and the length is on the upstream's answer - so the
 * fetch goes first, on a thread, and this task parks until that thread has
 * read the headers. Then the reply goes out and the same fetch's body streams
 * on through the pipe it has been filling meanwhile.
 *
 * What the thread learns lands in `what`, `worst` and `status` here, on this
 * task's own frame. The hook writes them before it pokes `tell` and never
 * touches them again, and this task does not return until it has been poked -
 * so the frame is alive for every write and every read of it. Nothing is
 * allocated for this, and nothing has to be freed.
 */
static http_response_t wholeObject(http_request_t *req, const char *bucket,
                                   const char *key, int bodyToo) {

  s3seal_pull_t *job = calloc(1, sizeof *job);
  s3seal_seal_t what;
  int worst = -1;
  int status = 0;
  int body[2];
  int tell[2];
  unsigned char one;
  ssize_t heard;

  if (job == NULL)
    return problem(req, 500, "InternalError", "out of memory");

  if (pipe(body) != 0) {
    free(job);
    return problem(req, 500, "InternalError", "no pipe");
  }

  if (pipe(tell) != 0) {
    close(body[0]);
    close(body[1]);
    free(job);
    return problem(req, 500, "InternalError", "no pipe");
  }

  memset(&what, 0, sizeof what);

  snprintf(job->bucket, sizeof job->bucket, "%s", bucket);
  snprintf(job->key, sizeof job->key, "%s", key);

  job->whole = 1;
  job->into = body[1];
  job->tell = tell[1];
  job->learn.into = &what;
  job->learn.worstInto = &worst;
  job->learn.statusInto = &status;

  go readers @thread pullRun(job);

  /* until the thread has the headers - one byte, and it always comes */
  heard = read(tell[0], &one, 1);

  if (heard < 0) {
    meta_readable(tell[0]);
    heard = read(tell[0], &one, 1);
  }

  meta_letGo(tell[0]);
  close(tell[0]);

  if (heard != 1 || worst != 0) {

    /* the thread owns `job` and the writing end and closes both itself */
    close(body[0]);

    return status == 404 ? problem(req, 404, "NoSuchKey", "no such key")
                         : problem(req, 502, "InternalError",
                                   "the upstream would not say");
  }

  {
    http_response_t answer = req.reply(200);

    answer = answer.header("ETag", held(req, what.etag))
                 .header("Content-Length",
                         heldText(req, TEXT`${what.how.plain}`))
                 .header("Accept-Ranges", "bytes")
                 .mime(held(req, what.mime[0] != 0 ? what.mime
                                                   : "binary/octet-stream"));

    if (what.when[0] != 0)
      answer = answer.header("Last-Modified", held(req, what.when));

    if (!bodyToo || what.how.plain == 0) {
      close(body[0]);
      return answer.send();
    }

    return answer.stream(body[0]);
  }
}

static http_response_t getObject(http_request_t *req, int bodyToo) {

  char key[S3SEAL_KEY_MAX + 1];
  const char *bucket = req.param("bucket");
  const char *wants = req.header("range");
  s3seal_seal_t what;
  unsigned long long at = 0;
  unsigned long long want;
  int status = 0;
  int ranged = 0;

  keyOf(req, key, sizeof key);

  if (s3seal_settings.ours(key))
    return problem(req, 404, "NoSuchKey", "no such key");

  /**
   * A whole read asks once; a ranged one has to ask twice.
   *
   * The metadata is on the answer's own headers, so a body read needs no HEAD
   * in front of it - a round trip saved, and the end of a race: between a
   * HEAD and a GET the object can be rewritten, and then the key from the
   * first answer will not open the bytes of the second.
   *
   * A range cannot do that. Which sealed bytes to ask for is worked out from
   * the frame geometry, so the geometry has to be known before the request is
   * made. That one still asks twice and closes the gap with `If-Match`.
   */
  if (wants == NULL || strncmp(wants, "bytes=", 6) != 0)
    return wholeObject(req, bucket, key, bodyToo);

  if (s3seal_upstream.headOf(bucket, key, &what, &status) != 0)
    return status == 404
               ? problem(req, 404, "NoSuchKey", "no such key")
               : problem(req, 502, "InternalError",
                         "the upstream would not say");

  want = what.how.plain;

  /* `bytes=from-to`, and only the one form, which is all any S3 client sends */
  if (wants != NULL && strncmp(wants, "bytes=", 6) == 0) {

    unsigned long long from = 0;
    unsigned long long to = what.how.plain > 0 ? what.how.plain - 1 : 0;

    if (sscanf(wants + 6, "%llu-%llu", &from, &to) >= 1) {

      if (to >= what.how.plain)
        to = what.how.plain > 0 ? what.how.plain - 1 : 0;

      at = from;
      want = to >= from ? to - from + 1 : 0;
      ranged = 1;
    }
  }

  {
    /**
     * The header strings live in `req->scratch`, which lasts exactly as long
     * as the request. A thread-local would be shared with every other request
     * this carrier picks up while this one is parked on the upstream, and two
     * concurrent ranges would swap their `Content-Range`.
     */
    http_response_t answer = req.reply(ranged ? 206 : 200);
    unsigned long long last = at + (want > 0 ? want - 1 : 0);

    answer = answer.header("ETag", held(req, what.etag))
                 .header("Content-Length", heldText(req, TEXT`${want}`))
                 .header("Accept-Ranges", "bytes")
                 .mime(held(req, what.mime[0] != 0
                                     ? what.mime
                                     : "binary/octet-stream"));

    if (what.when[0] != 0)
      answer = answer.header("Last-Modified", held(req, what.when));

    if (ranged)
      answer = answer.header(
          "Content-Range",
          heldText(req, TEXT`bytes ${at}-${last}/${what.how.plain}`));

    if (!bodyToo || want == 0)
      return answer.send();

    /* --------------------------------------------------- and the body */

    {
      s3seal_pull_t *job = calloc(1, sizeof *job);
      int both[2];

      if (job == NULL)
        return problem(req, 500, "InternalError", "out of memory");

      if (pipe(both) != 0) {
        free(job);
        return problem(req, 500, "InternalError", "no pipe");
      }

      snprintf(job->bucket, sizeof job->bucket, "%s", bucket);
      snprintf(job->key, sizeof job->key, "%s", key);

      job->what = what;
      job->at = at;
      job->want = want;
      job->into = both[1];

      go readers @thread pullRun(job);

      return answer.stream(both[0]);
    }
  }
}

static http_response_t onGet(http_request_t *req) { return getObject(req, 1); }
static http_response_t onHead(http_request_t *req) { return getObject(req, 0); }

static http_response_t onDelete(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  fetch_answer_t gone;

  if (asked(req, "uploadId"))
    return abortUpload(req);

  keyOf(req, key, sizeof key);

  if (s3seal_settings.ours(key))
    return problem(req, 403, "AccessDenied", "that prefix is the proxy's");

  if (s3seal_upstream.pass("DELETE", req.param("bucket"), key, NULL, &gone) !=
      0)
    return problem(req, 502, "InternalError", "the upstream would not say");

  defer gone.release();

  return req.reply(gone.status == 0 ? 204 : gone.status).send();
}

/* ---------------------------------------------------------------- buckets */

/* ---------------------------------------------------------------- listing */

/** `needle` in `[from, to)`, or NULL. The body is NUL-terminated past `to`. */
static const char *within(const char *from, const char *to,
                          const char *needle) {

  const char *found = strstr(from, needle);

  return found != NULL && found < to ? found : NULL;
}

/**
 * Whether one `<Contents>` or `<CommonPrefixes>` entry names something under
 * the scratch prefix.
 *
 * The name is compared as it came and percent-decoded as well, because a
 * client that asked for `encoding-type=url` gets every name encoded and the
 * slash in the prefix with it.
 */
static int hidden(const char *open, const char *shut) {

  const char *name = within(open, shut, "<Key>");
  size_t skip = 5;
  const char *end;
  char raw[S3SEAL_KEY_MAX * 3 + 1];
  char plain[S3SEAL_KEY_MAX + 1];

  if (name == NULL) {
    name = within(open, shut, "<Prefix>");
    skip = 8;
  }

  if (name == NULL)
    return 0;

  name += skip;
  end = within(name, shut, "</");

  if (end == NULL || (size_t)(end - name) >= sizeof raw)
    return 0;

  memcpy(raw, name, (size_t)(end - name));
  raw[end - name] = 0;

  s3seal_unescape(raw, plain, sizeof plain);

  return s3seal_settings.ours(raw) || s3seal_settings.ours(plain);
}

/**
 * The next entry at or after `at`, with `*shut` set past its end - or NULL.
 *
 * Where each kind was last seen is kept in `seen`, so a listing of a thousand
 * keys is searched once from front to back rather than once per key. Start
 * both at the body.
 */
static const char *nextEntry(const char *at, const char *seen[2],
                             const char **shut) {

  static const char *const opens[2] = {"<Contents>", "<CommonPrefixes>"};
  static const char *const shuts[2] = {"</Contents>", "</CommonPrefixes>"};
  int which = -1;

  for (int kind = 0; kind < 2; ++kind) {

    /* behind us, or not yet looked for: `seen` starts out at the body */
    if (seen[kind] != NULL &&
        (seen[kind] < at ||
         strncmp(seen[kind], opens[kind], strlen(opens[kind])) != 0))
      seen[kind] = strstr(at, opens[kind]);

    if (seen[kind] != NULL && (which < 0 || seen[kind] < seen[which]))
      which = kind;
  }

  if (which < 0)
    return NULL;

  *shut = strstr(seen[which], shuts[which]);

  if (*shut == NULL)
    return NULL;

  *shut += strlen(shuts[which]);

  return seen[which];
}

/**
 * `[from, to)` copied out, with the one number inside `tag` rewritten.
 *
 * `<Size>` becomes the plaintext size - unless the stored size is not one a
 * sealed object can have, which means the object was there before we were
 * and its size is already the truth. `<KeyCount>` loses the entries that
 * were hidden.
 */
static void copyRewriting(s3seal_buf_t *out, const char *from, const char *to,
                          const char *tag, unsigned long long hiddenCount) {

  const char *found = within(from, to, tag);
  const char *value;
  const char *stop;
  unsigned long long said;

  if (found == NULL) {
    out->addn(from, (size_t)(to - from));
    return;
  }

  value = found + strlen(tag);
  stop = within(value, to, "<");

  if (stop == NULL) {
    out->addn(from, (size_t)(to - from));
    return;
  }

  said = strtoull(value, NULL, 10);

  out->addn(from, (size_t)(value - from));

  if (tag[1] == 'S') {
    int ok = 0;
    unsigned long long plain = s3seal_plainSize(said, &ok);

    out->addText(TEXT`${ok ? plain : said}`);
  } else {
    out->addText(TEXT`${said > hiddenCount ? said - hiddenCount : 0}`);
  }

  out->addn(stop, (size_t)(to - stop));
}

/**
 * A listing, with the sizes put right.
 *
 * The upstream reports what it holds, which is the plaintext plus twenty-five
 * bytes for every sixty-four kilobyte frame. A client comparing that against
 * what it uploaded sees every object grow, so each `<Size>` is rewritten -
 * and it can be, without reading a single object, because the framing is a
 * fixed stride and the arithmetic runs backwards.
 *
 * The scratch prefix is dropped on the way past, since parts of an upload in
 * progress are ours and not the bucket's: every `<Contents>` under it, and
 * every `<CommonPrefixes>` that is inside it. A common prefix that merely
 * *leads* to it - `.s3seal/` in a listing with a delimiter - stays, because a
 * client may keep keys of its own under that, and hiding a client's keys is
 * worse than showing one folder too many.
 *
 * Two passes, because `<KeyCount>` comes before the entries it counts.
 */
static http_response_t listing(http_request_t *req, fetch_answer_t *got) {

  s3seal_buf_t *out = &s3seal_answer;
  const char *body = got->body != NULL ? got->body : "";
  const char *end = body + strlen(body);
  const char *seen[2] = {body, body};
  const char *shut = NULL;
  const char *entry;
  const char *at;
  unsigned long long hiddenCount = 0;

  out->count = 0;
  out->broke = 0;

  for (at = body; (entry = nextEntry(at, seen, &shut)) != NULL; at = shut)
    hiddenCount += (unsigned long long)hidden(entry, shut);

  seen[0] = body;
  seen[1] = body;
  entry = nextEntry(body, seen, &shut);

  /* everything in front of the first entry, which is where the count is */
  copyRewriting(out, body, entry != NULL ? entry : end, "<KeyCount>",
                hiddenCount);

  while (entry != NULL) {

    const char *after = shut;
    const char *next;

    if (!hidden(entry, after))
      copyRewriting(out, entry, after, "<Size>", 0);

    next = nextEntry(after, seen, &shut);

    /* whatever sits between two entries, or after the last one */
    out->addn(after, (size_t)((next != NULL ? next : end) - after));

    entry = next;
  }

  if (out->broke)
    return problem(req, 500, "InternalError", "out of memory");

  return req.reply(200).bytes("application/xml", out->at, out->count);
}

static http_response_t onBucketGet(http_request_t *req) {

  fetch_answer_t got;
  http_response_t answer;

  if (s3seal_upstream.pass("GET", req.param("bucket"), NULL,
                           req->queryString, &got) != 0)
    return problem(req, 502, "InternalError", "the upstream would not say");

  defer got.release();

  if (!got.ok)
    return req.reply(got.status).bytes("application/xml", got.body,
                                       got.length);

  answer = listing(req, &got);

  return answer;
}

static http_response_t onBucketOther(http_request_t *req) {

  fetch_answer_t got;

  if (s3seal_upstream.pass(req->method, req.param("bucket"), NULL,
                           req->queryString, &got) != 0)
    return problem(req, 502, "InternalError", "the upstream would not say");

  defer got.release();

  return req.reply(got.status).bytes("application/xml",
                                     got.body != NULL ? got.body : "",
                                     got.length);
}

static http_response_t listBuckets(http_request_t *req) {

  fetch_answer_t got;

  if (s3seal_upstream.pass("GET", "", NULL, NULL, &got) != 0)
    return problem(req, 502, "InternalError", "the upstream would not say");

  defer got.release();

  return req.reply(got.status).bytes("application/xml",
                                     got.body != NULL ? got.body : "",
                                     got.length);
}

/* -------------------------------------------------------------- multipart */

/** A query parameter, or "". */
static const char *askOf(http_request_t *req, const char *name) {
  return req.query(name);
}

/** Whether a query parameter is present at all, with or without a value. */
static int asked(http_request_t *req, const char *name) {

  size_t want = strlen(name);
  const char *at = req->queryString;

  while (*at != 0) {

    const char *end = strchr(at, '&');
    size_t length = end != NULL ? (size_t)(end - at) : strlen(at);

    if ((length == want || (length > want && at[want] == '=')) &&
        strncmp(at, name, want) == 0)
      return 1;

    if (end == NULL)
      break;

    at = end + 1;
  }

  return 0;
}

static http_response_t startUpload(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  char id[33];
  const char *bucket = req.param("bucket");
  s3seal_buf_t *out = &s3seal_answer;

  keyOf(req, key, sizeof key);

  if (s3seal_settings.ours(key))
    return problem(req, 403, "AccessDenied", "that prefix is the proxy's");

  if (s3seal_upstream.begin(bucket, key, req.header("content-type"), id,
                            sizeof id) != 0)
    return problem(req, 502, "InternalError", "the upload could not be begun");

  out->count = 0;
  out->broke = 0;

  out->add("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<InitiateMultipartUploadResult><Bucket>");
  out->addXml(bucket);
  out->add("</Bucket><Key>");
  out->addXml(key);
  out->add("</Key><UploadId>");
  out->addXml(id);
  out->add("</UploadId></InitiateMultipartUploadResult>");

  return req.reply(200).bytes("application/xml", out->at, out->count);
}

static http_response_t uploadPart(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  char etag[S3SEAL_ETAG_MAX];
  const char *bucket = req.param("bucket");
  const char *id = askOf(req, "uploadId");
  int number = atoi(askOf(req, "partNumber"));
  s3seal_upload_t what;
  http_body_t body = req.readBody();

  keyOf(req, key, sizeof key);

  if (number < 1 || number > S3SEAL_PARTS_MAX)
    return problem(req, 400, "InvalidArgument", "that is not a part number");

  if (body.length > s3seal_settings.maxPart)
    return problem(req, 413, "EntityTooLarge", "that part is too large");

  {
    const char *encoding = req.header("content-encoding");

    if (encoding != NULL && strstr(encoding, "aws-chunked") != NULL) {

      int worst, size_t length =
          s3seal_dechunk((char *)body.bytes, body.length);

      if (worst != 0)
        return problem(req, 400, "MalformedChunkedBody", "bad chunk framing");

      body.length = length;
    }
  }

  if (s3seal_upstream.upload(bucket, id, &what) != 0)
    return problem(req, 404, "NoSuchUpload", "no such upload");

  /**
   * No size check here, and that is deliberate.
   *
   * A part has to be a whole number of frames - except the object's last one,
   * which is short by definition - and *which part is last is not knowable
   * when a part arrives*. Parts come out of order and the client says nothing
   * about how many there will be. Checking here rejected every upload whose
   * remainder happened to arrive first, which is most of them.
   *
   * So the check belongs at the completion, where the part list is finally
   * known. See `s3seal_proxy_t.finish`.
   */
  if (s3seal_upstream.part(id, &what, number, body.bytes, body.length, etag,
                           sizeof etag) != 0)
    return problem(req, 502, "InternalError", "the part could not be stored");

  return req.reply(200).header("ETag", held(req, etag)).send();
}

static http_response_t finishUpload(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  char etag[S3SEAL_ETAG_MAX];
  const char *bucket = req.param("bucket");
  const char *id = askOf(req, "uploadId");
  s3seal_upload_t what;
  s3seal_buf_t *out = &s3seal_answer;

  keyOf(req, key, sizeof key);

  /* the client's part list is read and dropped: what was actually parked is
     what gets assembled, and that is what the listing says */
  req.readBody();

  if (s3seal_upstream.upload(bucket, id, &what) != 0)
    return problem(req, 404, "NoSuchUpload", "no such upload");

  if (s3seal_upstream.finish(id, &what, etag, sizeof etag) != 0)
    return problem(req, 502, "InternalError",
                   "the upload could not be assembled");

  out->count = 0;
  out->broke = 0;

  out->add("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<CompleteMultipartUploadResult><Bucket>");
  out->addXml(bucket);
  out->add("</Bucket><Key>");
  out->addXml(key);
  out->add("</Key><ETag>");
  out->addXml(etag);
  out->add("</ETag></CompleteMultipartUploadResult>");

  return req.reply(200).bytes("application/xml", out->at, out->count);
}

static http_response_t abortUpload(http_request_t *req) {

  s3seal_upstream.abort(req.param("bucket"), askOf(req, "uploadId"));

  return req.reply(204).send();
}

static http_response_t onPost(http_request_t *req) {

  if (asked(req, "uploads"))
    return startUpload(req);

  if (asked(req, "uploadId"))
    return finishUpload(req);

  return problem(req, 501, "NotImplemented", "no such operation on an object");
}

/**
 * Which kind of PUT this is, decided **before** anybody reads the body.
 *
 * The first version dispatched inside `putObject`, after its declarations had
 * already run - and one of those declarations is `req.readBody()`. So the
 * body was consumed by the whole-object path and then asked for again by the
 * part path, which waited for bytes that had already been handed over. Every
 * multipart upload hung on its first part.
 *
 * Reading a body is not a question you can ask twice, so the branch has to
 * come first.
 */
static http_response_t onPut(http_request_t *req) {

  if (asked(req, "uploadId"))
    return uploadPart(req);

  return putObject(req);
}

/* ------------------------------------------------------ starting, stopping */

int s3seal_configure(void) { return s3seal_settings.read(); }

int s3seal_start(void) {

  if (s3seal_master.load(s3seal_settings.seed) != 0)
    return -1;

  s3seal_upstream.start(&s3seal_settings, &s3seal_master);

  s3seal_serving = 1;

  fprintf(stderr, "s3seal: sealing in front of %s\n",
          s3seal_settings.upstream);

  return 0;
}

void s3seal_stop(void) {

  if (!s3seal_serving)
    return;

  s3seal_serving = 0;

  /* the upstream pushes finish, and its connections close, before the
     settings they were made with go */
  s3seal_upstream.stop();

  s3seal_settings.drop();
}

void s3seal_routes(void) {

  http.use(guard);

  http.get("/", listBuckets);

  http.put("/:bucket", onBucketOther);
  http.remove("/:bucket", onBucketOther);
  http.head("/:bucket", onBucketOther);
  http.get("/:bucket", onBucketGet);

  http.put("/:bucket/*key", onPut);
  http.post("/:bucket/*key", onPost);
  http.get("/:bucket/*key", onGet);
  http.head("/:bucket/*key", onHead);
  http.remove("/:bucket/*key", onDelete);
}
