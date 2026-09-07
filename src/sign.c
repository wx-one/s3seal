#include "sign.h"
#include "frame.h"
#include "util.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- encoding */

/** Unreserved by RFC 3986, which is exactly what AWS leaves alone. */
static int plain(unsigned char c) {

  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
         c == '~';
}

size_t s3seal_encodePath(const char *from, char *into, size_t room) {

  size_t at = 0;

  for (const unsigned char *one = (const unsigned char *)from; *one != 0;
       ++one) {

    if (plain(*one) || *one == '/') {

      if (at + 2 > room)
        break;

      into[at++] = (char)*one;
      continue;
    }

    if (at + 4 > room)
      break;

    snprintf(into + at, room - at, "%%%02X", *one);
    at += 3;
  }

  into[at] = 0;

  return at;
}

int s3seal_urlFor(const char *upstream, const char *bucket, const char *key,
                  char *into, size_t room) {

  char encoded[S3SEAL_KEY_MAX * 3 + 1];

  if (key != NULL && key[0] != 0) {
    s3seal_encodePath(key, encoded, sizeof encoded - 1);
    return snprintf(into, room, "%s/%s/%s", upstream, bucket, encoded) <
                   (int)room
               ? 0
               : -1;
  }

  return snprintf(into, room, "%s/%s", upstream, bucket) < (int)room ? 0 : -1;
}

/* ------------------------------------------------------ the canonical form */

typedef struct {
  char name[128];
  const char *value;
} s3seal_field_t;

static int byName(const void *left, const void *right) {

  return strcmp(((const s3seal_field_t *)left)->name,
                ((const s3seal_field_t *)right)->name);
}

/** Lowercased, and only the ones S3 wants covered. */
static int wanted(const char *name) {

  return strcasecmp(name, "host") == 0 ||
         strncasecmp(name, "x-amz-", 6) == 0;
}

/**
 * The host out of a URL, which is what `Host:` has to say and what the
 * signature covers. curl writes the header itself, so it is never in the
 * call's list to be read back - it has to be worked out from the URL.
 */
static void hostOf(const char *url, char *into, size_t room) {

  const char *at = strstr(url, "://");
  const char *stop;
  size_t length;

  at = at != NULL ? at + 3 : url;

  stop = at + strcspn(at, "/?");
  length = (size_t)(stop - at);

  if (length >= room)
    length = room - 1;

  memcpy(into, at, length);
  into[length] = 0;
}

/** The path out of a URL, already encoded by whoever built it. */
static void pathOf(const char *url, char *into, size_t room) {

  const char *at = strstr(url, "://");
  const char *stop;
  size_t length;

  at = at != NULL ? at + 3 : url;
  at += strcspn(at, "/?");

  if (*at != '/') {
    snprintf(into, room, "/");
    return;
  }

  stop = at + strcspn(at, "?");
  length = (size_t)(stop - at);

  if (length >= room)
    length = room - 1;

  memcpy(into, at, length);
  into[length] = 0;
}

/**
 * The query, sorted by name.
 *
 * The values arrive already encoded - `fetch_call_t.query` escaped them - and
 * SigV4 wants them encoded, so nothing is re-encoded here. Doing it twice is
 * the classic way to produce a signature that is right about a URL nobody
 * sent.
 */
static void queryOf(const char *url, char *into, size_t room) {

  const char *at = strchr(url, '?');
  char parts[32][512];
  size_t count = 0;

  into[0] = 0;

  if (at == NULL)
    return;

  ++at;

  while (*at != 0 && count < 32) {

    size_t length = strcspn(at, "&");

    if (length >= sizeof parts[0])
      length = sizeof parts[0] - 1;

    memcpy(parts[count], at, length);
    parts[count][length] = 0;

    /* a parameter with no value is still a parameter, and needs the `=` */
    if (strchr(parts[count], '=') == NULL &&
        length + 2 < sizeof parts[0])
      strcat(parts[count], "=");

    ++count;

    at += strcspn(at, "&");

    if (*at == '&')
      ++at;
  }

  qsort(parts, count, sizeof parts[0], (int (*)(const void *,
                                                const void *))strcmp);

  for (size_t one = 0; one < count; ++one) {

    size_t used = strlen(into);

    if (used + strlen(parts[one]) + 2 >= room)
      break;

    snprintf(into + used, room - used, "%s%s", one > 0 ? "&" : "",
             parts[one]);
  }
}

/* ------------------------------------------------------------- the signing */

static void signingKey(const char *secret, const char *day, const char *region,
                       const char *service, unsigned char *into) {

  unsigned char step[32];
  char first[300];

  snprintf(first, sizeof first, "AWS4%s", secret);

  s3seal_hmacSha256(first, strlen(first), day, strlen(day), step);
  s3seal_hmacSha256(step, sizeof step, region, strlen(region), step);
  s3seal_hmacSha256(step, sizeof step, service, strlen(service), step);
  s3seal_hmacSha256(step, sizeof step, "aws4_request", 12, into);
}

void s3seal_sign(void *with, fetch_call_t *call) {

  s3seal_signer_t *who = with;
  s3seal_field_t fields[32];
  size_t count = 0;

  char host[256];
  char path[S3SEAL_KEY_MAX * 3 + 8];
  char query[1024];
  char amzDate[32];
  char day[16];
  char signed_[512] = "";
  char scope[256];
  char digest[65];
  char header[1024];
  unsigned char key[32];
  unsigned char mac[32];
  char signature[65];
  const char *bodyHash = "UNSIGNED-PAYLOAD";
  s3seal_buf_t canonical = {0};
  s3seal_buf_t toSign = {0};

  defer canonical.drop();
  defer toSign.drop();

  s3seal_amzTime(s3seal_now(), amzDate, sizeof amzDate);
  s3seal_amzDay(s3seal_now(), day, sizeof day);

  hostOf(call->url, host, sizeof host);
  pathOf(call->url, path, sizeof path);
  queryOf(call->url, query, sizeof query);

  /**
   * `Host` is not in the call's header list - curl writes it - so it is put
   * in here, and the date with it. Both have to be signed and both have to
   * reach the wire, so both are added to the call as well.
   */
  snprintf(fields[count].name, sizeof fields[count].name, "host");
  fields[count].value = host;
  ++count;

  *call = call->header("x-amz-date", amzDate);

  snprintf(fields[count].name, sizeof fields[count].name, "x-amz-date");
  fields[count].value = amzDate;
  ++count;

  /**
   * Everything the caller already put on the call that S3 covers.
   *
   * Read back out of curl's own list, which is the only place they are - and
   * the reason the hook takes the call rather than a bag of strings.
   */
  for (struct curl_slist *one = call->headers;
       one != NULL && count < 32; one = one->next) {

    const char *colon = strchr(one->data, ':');
    size_t length;

    if (colon == NULL)
      continue;

    length = (size_t)(colon - one->data);

    if (length >= sizeof fields[count].name)
      continue;

    memcpy(fields[count].name, one->data, length);
    fields[count].name[length] = 0;

    if (!wanted(fields[count].name))
      continue;

    for (size_t at = 0; at < length; ++at)
      fields[count].name[at] = (char)tolower((unsigned char)
                                             fields[count].name[at]);

    /* already there: the date we just added, which curl would then send twice */
    if (strcmp(fields[count].name, "x-amz-date") == 0)
      continue;

    ++colon;

    while (*colon == ' ')
      ++colon;

    fields[count].value = colon;

    if (strcmp(fields[count].name, "x-amz-content-sha256") == 0)
      bodyHash = colon;

    ++count;
  }

  qsort(fields, count, sizeof fields[0], byName);

  /* ------------------------------------------------- the canonical request */

  canonical.addf("%s\n%s\n%s\n", call->method, path, query);

  for (size_t at = 0; at < count; ++at) {

    canonical.addf("%s:%s\n", fields[at].name, fields[at].value);

    {
      size_t used = strlen(signed_);
      size_t length = strlen(fields[at].name);

      /**
       * Appended by hand rather than with `snprintf`.
       *
       * Thirty-two names of a hundred and twenty-eight would not fit here,
       * and a signed-headers list that was quietly cut is a 403 the upstream
       * gives no reason for - so the overflow is refused rather than
       * truncated. Written this way because the bound is on a `strlen` gcc
       * cannot follow, and a `-Wformat-truncation` it cannot be talked out of
       * is worth one loop.
       */
      if (used + length + 2 >= sizeof signed_) {
        canonical.broke = 1;
        break;
      }

      if (at > 0)
        signed_[used++] = ';';

      memcpy(signed_ + used, fields[at].name, length);

      signed_[used + length] = 0;
    }
  }

  canonical.addf("\n%s\n%s", signed_, bodyHash);

  if (canonical.broke)
    return;

  s3seal_sha256Hex(canonical.at, canonical.count, digest);

  snprintf(scope, sizeof scope, "%s/%s/%s/aws4_request", day, who->region,
           who->service != NULL ? who->service : "s3");

  toSign.addf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, scope, digest);

  if (toSign.broke)
    return;

  signingKey(who->secret, day, who->region,
             who->service != NULL ? who->service : "s3", key);

  s3seal_hmacSha256(key, sizeof key, toSign.at, toSign.count, mac);
  s3seal_toHex(mac, sizeof mac, signature);

  snprintf(header, sizeof header,
           "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
           who->access, scope, signed_, signature);

  *call = call->header("authorization", header);
}
