#include "sigv4.h"
#include "crypt.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum s3sealSigLimit {
  /** What AWS allows between a request's date and the server's. */
  S3SEAL_SKEW = 900
};

/* --------------------------------------------------- the header, apart */

/**
 * Copies the value of `Name=` out of a comma-separated list.
 *
 * `from` must already be past the algorithm word. The header reads
 * `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...` - a
 * *space* after the algorithm and commas between the fields - and walking it
 * as though it were commas throughout finds nothing at all, because the first
 * comma is already past `Credential`.
 */
static int fieldOf(const char *from, const char *name, char *into,
                   size_t room) {

  size_t length = strlen(name);
  const char *at = from;

  into[0] = 0;

  while (*at != 0) {

    const char *stop;
    size_t take;

    while (*at == ' ' || *at == ',')
      ++at;

    if (strncmp(at, name, length) != 0 || at[length] != '=') {

      stop = strchr(at, ',');

      if (stop == NULL)
        return -1;

      at = stop + 1;
      continue;
    }

    at += length + 1;
    stop = strchr(at, ',');
    take = stop != NULL ? (size_t)(stop - at) : strlen(at);

    if (take + 1 > room)
      return -1;

    memcpy(into, at, take);
    into[take] = 0;

    return 0;
  }

  return -1;
}

s3seal_auth_t s3seal_signature_t.read(s3seal_signature_t *self,
                                    http_request_t *req) {

  const char *header = req.header("authorization");
  const char *given = req.header("x-amz-content-sha256");
  char credential[320];
  char *cut;

  memset(self, 0, sizeof *self);

  if (header == NULL || header[0] == 0)
    return S3SEAL_AUTH_MISSING;

  if (!s3seal_startsWith(header, "AWS4-HMAC-SHA256"))
    return S3SEAL_AUTH_MALFORMED;

  {
    const char *space = strchr(header, ' ');
    const char *fields;

    if (space == NULL)
      return S3SEAL_AUTH_MALFORMED;

    fields = space + 1;

    if (fieldOf(fields, "Credential", credential, sizeof credential) != 0 ||
        fieldOf(fields, "SignedHeaders", self->signedHeaders,
                sizeof self->signedHeaders) != 0 ||
        fieldOf(fields, "Signature", self->signature,
                sizeof self->signature) != 0)
      return S3SEAL_AUTH_MALFORMED;
  }

  /* accessKey/day/region/service/aws4_request */
  {
    char *piece = credential;
    char *parts[5];
    int count = 0;

    while (count < 5) {

      parts[count++] = piece;

      cut = strchr(piece, '/');

      if (cut == NULL)
        break;

      *cut = 0;
      piece = cut + 1;
    }

    if (count != 5)
      return S3SEAL_AUTH_MALFORMED;

    snprintf(self->access, sizeof self->access, "%s", parts[0]);
    snprintf(self->day, sizeof self->day, "%s", parts[1]);
    snprintf(self->region, sizeof self->region, "%s", parts[2]);
    snprintf(self->service, sizeof self->service, "%s", parts[3]);
  }

  snprintf(self->amzDate, sizeof self->amzDate, "%s",
           req.header("x-amz-date") != NULL ? req.header("x-amz-date") : "");

  snprintf(self->bodyHash, sizeof self->bodyHash, "%s",
           given != NULL ? given : "UNSIGNED-PAYLOAD");

  if (strcmp(self->bodyHash, "UNSIGNED-PAYLOAD") == 0)
    self->payload = S3SEAL_PAYLOAD_UNSIGNED;
  else if (s3seal_startsWith(self->bodyHash, "STREAMING-"))
    self->payload = S3SEAL_PAYLOAD_CHUNKED;
  else
    self->payload = S3SEAL_PAYLOAD_HASHED;

  return S3SEAL_AUTH_OK;
}

/* ------------------------------------------------- the canonical request */

/**
 * The query string, rebuilt: every name and value decoded and encoded again,
 * sorted by name.
 *
 * Decoded and re-encoded rather than passed through, because what a client
 * sent and what the canonical form wants are two encodings of the same thing
 * and only one of them is the one AWS specified. Passing it through works
 * until a client encodes a character we would not have.
 */
typedef struct {
  char name[256];
  char value[1024];
} s3seal_pair_t;

static void canonicalQuery(const char *from, s3seal_buf_t *into) {

  s3seal_pair_t pairs[64];
  int count = 0;

  while (*from != 0 && count < 64) {

    const char *end = strchr(from, '&');
    size_t length = end != NULL ? (size_t)(end - from) : strlen(from);
    const char *equals = memchr(from, '=', length);

    char rawName[512];
    char rawValue[2048];
    size_t nameLength = equals != NULL ? (size_t)(equals - from) : length;

    if (nameLength < sizeof rawName) {

      memcpy(rawName, from, nameLength);
      rawName[nameLength] = 0;

      rawValue[0] = 0;

      if (equals != NULL) {

        size_t valueLength = length - nameLength - 1;

        if (valueLength < sizeof rawValue) {
          memcpy(rawValue, equals + 1, valueLength);
          rawValue[valueLength] = 0;
        }
      }

      s3seal_unescape(rawName, pairs[count].name, sizeof pairs[count].name);
      s3seal_unescape(rawValue, pairs[count].value, sizeof pairs[count].value);

      ++count;
    }

    if (end == NULL)
      break;

    from = end + 1;
  }

  /* by name, then by value, which is what SigV4 says canonical order is */
  qsort(pairs, (size_t)count, sizeof pairs[0],
        (const void *a, const void *b) => {
          const s3seal_pair_t *one = a;
          const s3seal_pair_t *two = b;
          int said = strcmp(one->name, two->name);

          return said != 0 ? said : strcmp(one->value, two->value);
        });

  for (int at = 0; at < count; ++at) {

    if (at != 0)
      into->add("&");

    into->addUri(pairs[at].name, 0);
    into->add("=");
    into->addUri(pairs[at].value, 0);
  }
}

/** Trims the ends and squeezes runs of spaces, which is what SigV4 wants. */
static void addHeaderValue(s3seal_buf_t *into, const char *value) {

  const char *at = value;
  int spaced = 0;

  while (*at == ' ' || *at == '\t')
    ++at;

  {
    size_t length = strlen(at);

    while (length > 0 && (at[length - 1] == ' ' || at[length - 1] == '\t'))
      --length;

    for (size_t step = 0; step < length; ++step) {

      if (at[step] == ' ' || at[step] == '\t') {

        if (!spaced)
          into->add(" ");

        spaced = 1;
        continue;
      }

      spaced = 0;
      into->addn(at + step, 1);
    }
  }
}

static void canonicalRequest(http_request_t *req, s3seal_signature_t *sig,
                             s3seal_buf_t *into) {

  const char *ask = strchr(req->path, '?');
  size_t pathLength = ask != NULL ? (size_t)(ask - req->path)
                                  : strlen(req->path);

  into->add(req->method);
  into->add("\n");

  /**
   * The path exactly as it arrived. S3 is the one AWS service that does not
   * normalise and does not encode a second time, and `r->unparsed_uri` is
   * what the module hands over - which is the reason it hands that over
   * rather than nginx's decoded `uri`.
   */
  into->addn(req->path, pathLength);
  into->add("\n");

  canonicalQuery(req->queryString, into);
  into->add("\n");

  {
    char names[1024];
    char *at = names;

    snprintf(names, sizeof names, "%s", sig->signedHeaders);

    while (at != NULL && *at != 0) {

      char *cut = strchr(at, ';');
      const char *value;

      if (cut != NULL)
        *cut = 0;

      value = req.header(at);

      into->add(at);
      into->add(":");
      addHeaderValue(into, value != NULL ? value : "");
      into->add("\n");

      at = cut != NULL ? cut + 1 : NULL;
    }
  }

  into->add("\n");
  into->add(sig->signedHeaders);
  into->add("\n");
  into->add(sig->bodyHash);
}

/* ------------------------------------------------------- the signing key */

static void signingKey(const char *secret, const char *day,
                       const char *region, const char *service,
                       unsigned char *into) {

  unsigned char step[32];
  char first[256];

  snprintf(first, sizeof first, "AWS4%s", secret);

  s3seal_hmacSha256(first, strlen(first), day, strlen(day), step);
  s3seal_hmacSha256(step, sizeof step, region, strlen(region), step);
  s3seal_hmacSha256(step, sizeof step, service, strlen(service), step);
  s3seal_hmacSha256(step, sizeof step, "aws4_request", 12, into);
}

/** A comparison whose duration does not say how much of it matched. */
static int sameSecret(const char *a, const char *b) {

  size_t length = strlen(a);
  unsigned char different = 0;

  if (length != strlen(b))
    return 0;

  for (size_t at = 0; at < length; ++at)
    different |= (unsigned char)(a[at] ^ b[at]);

  return different == 0;
}

s3seal_auth_t s3seal_verify(s3seal_config_t *config, http_request_t *req,
                          char *who, size_t room) {

  s3seal_signature_t sig;
  s3seal_auth_t said = sig.read(req);
  s3seal_buf_t canonical = {0};
  s3seal_buf_t toSign = {0};

  const char *secret;
  unsigned char key[32];
  unsigned char mac[32];
  char digest[65];
  char mine[65];

  if (said != S3SEAL_AUTH_OK)
    return said;

  snprintf(who, room, "%s", sig.access);

  secret = config->secretFor(sig.access);

  if (secret == NULL)
    return S3SEAL_AUTH_UNKNOWN_KEY;

  /**
   * The clock before the signature, because a stale request is a different
   * answer from a wrong one and a client that is simply out of step should
   * be told which of the two it is.
   */
  {
    long long when = s3seal_readAmzTime(sig.amzDate);
    long long now = s3seal_now();
    long long apart = when > now ? when - now : now - when;

    if (when < 0 || apart > S3SEAL_SKEW)
      return S3SEAL_AUTH_SKEWED;
  }

  defer canonical.drop();
  defer toSign.drop();

  canonicalRequest(req, &sig, &canonical);

  s3seal_sha256Hex(canonical.at, canonical.count, digest);

  toSign.add("AWS4-HMAC-SHA256\n");
  toSign.add(sig.amzDate);
  toSign.add("\n");
  toSign.addf("%s/%s/%s/aws4_request\n", sig.day, sig.region, sig.service);
  toSign.add(digest);

  if (canonical.broke || toSign.broke)
    return S3SEAL_AUTH_MALFORMED;

  signingKey(secret, sig.day, sig.region, sig.service, key);

  s3seal_hmacSha256(key, sizeof key, toSign.at, toSign.count, mac);
  s3seal_toHex(mac, sizeof mac, mine);

  return sameSecret(mine, sig.signature) ? S3SEAL_AUTH_OK
                                         : S3SEAL_AUTH_BAD_SIGNATURE;
}

/* ------------------------------------------------------------ aws-chunked */

/**
 * `<hex length>[;chunk-signature=...]\r\n<data>\r\n`, repeated, ending with a
 * chunk of length zero and then whatever trailer the client added.
 *
 * Rewritten in place. The plain bytes are always shorter than the framed
 * ones, so the read cursor is always ahead of the write cursor and nothing is
 * overwritten before it has been moved.
 */
int, size_t s3seal_dechunk(char *body, size_t length) {

  size_t from = 0;
  size_t to = 0;

  for (;;) {

    size_t lineEnd = from;
    size_t size = 0;
    int digits = 0;

    while (lineEnd < length && body[lineEnd] != '\r' && body[lineEnd] != ';')
      ++lineEnd;

    if (lineEnd >= length)
      return -1, to;

    for (size_t at = from; at < lineEnd; ++at) {

      char one = body[at];
      int value;

      if (one >= '0' && one <= '9')
        value = one - '0';
      else if (one >= 'a' && one <= 'f')
        value = one - 'a' + 10;
      else if (one >= 'A' && one <= 'F')
        value = one - 'A' + 10;
      else
        return -1, to;

      size = size * 16 + (size_t)value;
      ++digits;
    }

    if (digits == 0)
      return -1, to;

    /* past the extensions, to the end of the line */
    while (lineEnd < length && body[lineEnd] != '\n')
      ++lineEnd;

    if (lineEnd >= length)
      return -1, to;

    from = lineEnd + 1;

    if (size == 0)
      break;

    if (from + size > length)
      return -1, to;

    memmove(body + to, body + from, size);

    to += size;
    from += size + 2; /* the \r\n after the data */
  }

  return 0, to;
}
