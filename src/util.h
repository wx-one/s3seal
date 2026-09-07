#ifndef S3SEAL_UTIL_H
#define S3SEAL_UTIL_H

/**
 * Strings, bytes, time and a growing buffer.
 *
 * Nothing here knows what S3 is. It is the layer every other file leans on,
 * and it is deliberately small: a buffer that grows, hex both ways, the two
 * date formats AWS uses, and a CRC for the log.
 */

#include "s3seal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ text */

/** A copy the caller owns, or NULL. */
@owns char *s3seal_dupn(const char *from, size_t length);
@owns char *s3seal_dup(const char *from);

/** `a` and `b` with `between` in the middle, in one allocation. */
@owns char *s3seal_join(const char *a, const char *between, const char *b);

/** Case-insensitive compare, because header and method names are. */
int s3seal_same(const char *a, const char *b);

/** Whether `text` starts with `with`. */
int s3seal_startsWith(const char *text, const char *with);

/**
 * Whether a bucket name is one S3 would accept.
 *
 * Narrower than AWS on purpose: a name that is not this is a name that will
 * one day be a host name or a directory, and both have opinions.
 */
int s3seal_bucketOk(const char *name);

/** Whether a key is one we will store: non-empty, no NUL, under the limit. */
int s3seal_keyOk(const char *key);

/* ------------------------------------------------------------------ bytes */

void s3seal_toHex(const unsigned char *from, size_t length, char *into);
int s3seal_fromHex(const char *from, unsigned char *into, size_t room);

/**
 * The CRC the metadb log puts in front of every record.
 *
 * Not a checksum against an adversary - the wrapping key is what that is for.
 * This answers one question: did the last record finish being written before
 * the machine stopped. A tail that fails it is a tail that is cut off.
 */
unsigned int s3seal_crc32(const void *bytes, size_t length, unsigned int from);

/* ------------------------------------------------------------------- time */

long long s3seal_now(void);

/** `2026-09-04T14:33:12.000Z`, which is what S3 puts in a listing. */
void s3seal_iso8601(long long when, char *into, size_t room);

/** `20260904T143312Z`, which is what SigV4 signs. */
void s3seal_amzTime(long long when, char *into, size_t room);

/** `20260904`, the date half of it. */
void s3seal_amzDay(long long when, char *into, size_t room);

/**
 * `Thu, 04 Sep 2026 15:35:40 GMT`, which is the only thing `Last-Modified`
 * may be.
 *
 * Not the same as `s3seal_iso8601`, and the difference is not cosmetic: an S3
 * listing carries ISO 8601 inside its XML, and an HTTP header carries RFC
 * 7231's date. Sending the first where the second belongs makes rclone print
 * five parse failures and give up on the object.
 */
void s3seal_httpDate(long long when, char *into, size_t room);

/** Reads back what `s3seal_amzTime` writes, for the clock-skew check. */
long long s3seal_readAmzTime(const char *text);

/* --------------------------------------------------------------- a buffer */

/**
 * Bytes that grow, with the appends a document generator actually makes.
 *
 * Not `char[]`, meta's growable array, and the reason is the shape of the
 * work rather than a preference: an XML listing is built out of runs of text,
 * and `push` per character would be the wrong instrument. This grows by
 * doubling and appends a run at a time.
 *
 * `drop` rather than `release`, because `release` is the word meta's own
 * containers answer to and a type that is not one should not borrow it.
 */
typedef struct s3seal_buf_t {
  char *at;
  size_t count;
  size_t room;

  /** Set once an allocation failed; every later append is a no-op. */
  int broke;
} s3seal_buf_t;

int s3seal_buf_t.grow(s3seal_buf_t *self, size_t more);
int s3seal_buf_t.addn(s3seal_buf_t *self, const void *bytes, size_t length);
int s3seal_buf_t.add(s3seal_buf_t *self, const char *text);
int s3seal_buf_t.addf(s3seal_buf_t *self, const char *shape, ...);

/** The same, with `& < > " '` written the way XML needs them. */
int s3seal_buf_t.addXml(s3seal_buf_t *self, const char *text);

/** And with every byte outside the unreserved set percent-encoded. */
int s3seal_buf_t.addUri(s3seal_buf_t *self, const char *text, int keepSlash);

void s3seal_buf_t.drop(s3seal_buf_t *self);

/** Percent-decoding, in place-safe form: `into` may be `from`. */
size_t s3seal_unescape(const char *from, char *into, size_t room);

#endif /* S3SEAL_UTIL_H */
