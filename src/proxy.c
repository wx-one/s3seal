#include "proxy.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Where the time went, when somebody asks.
 *
 * Off unless `S3SEAL_TIMING` is set, because a line per request is a log
 * nobody reads - but "the proxy is half the speed of the upstream" is a
 * question that comes up once a month and guessing at it is how the wrong
 * thing gets optimised.
 */
static int s3seal_timing = -1;

static double s3seal_clock(void) {

  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);

  return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
}

void s3seal_proxy_t.start(s3seal_proxy_t *self, s3seal_config_t *config,
                          s3seal_master_t *master) {

  self->config = config;
  self->master = master;

  self->signer.access = config->upstreamAccess;
  self->signer.secret = config->upstreamSecret;
  self->signer.region = config->region;
  self->signer.service = "s3";
}

/** Every call goes out the same way, so the sameness is written once. */
static fetch_call_t call(s3seal_proxy_t *self, const char *method,
                         const char *url) {

  return meta_fetch(method, url)
      .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
      .before(s3seal_sign, &self->signer);
}

/* ------------------------------------------------------------------ head */

int s3seal_proxy_t.headOf(s3seal_proxy_t *self, const char *bucket,
                          const char *key, s3seal_seal_t *into, int *status) {

  char url[S3SEAL_URL_MAX];
  char *bound = s3seal_join(bucket, "/", key);
  unsigned char blob[S3SEAL_BLOB];
  fetch_answer_t got;
  const char *seal;
  int worst = -1;

  memset(into, 0, sizeof *into);

  if (bound == NULL ||
      s3seal_urlFor(self->config->upstream, bucket, key, url, sizeof url) != 0) {
    free(bound);
    return -1;
  }

  defer free(bound);

  got = call(self, "HEAD", url).nobody().send();

  defer got.release();

  *status = got.failed ? 502 : got.status;

  if (!got.ok) {

    if (got.status != 404)
      fprintf(stderr, "s3seal: upstream HEAD %s/%s: %d %s\n", bucket, key,
              got.status, got.failed ? got.why : "");

    return -1;
  }

  into->stored = strtoull(got.header("content-length"), NULL, 10);

  /* bounded: a header comes out of a kilobyte of room and these fields are
     smaller, so the truncation is deliberate rather than discovered */
  snprintf(into->mime, sizeof into->mime, "%.127s", got.header("content-type"));
  snprintf(into->when, sizeof into->when, "%.63s",
           got.header("last-modified"));

  seal = got.header("x-amz-meta-seal");

  /**
   * No sealing metadata: an object that was in the bucket before we were.
   *
   * Answering "not ours" rather than failing is the difference between a
   * proxy you can put in front of a bucket that already has things in it and
   * one that requires an empty one.
   */
  if (seal[0] == 0) {
    into->plain = 1;
    into->how.plain = into->stored;
    snprintf(into->etag, sizeof into->etag, "%.63s", got.header("etag"));
    return 0;
  }

  /* it answers how many bytes it decoded, and negative for anything else */
  if (s3seal_fromHex(seal, blob, sizeof blob) != (int)sizeof blob) {
    fprintf(stderr, "s3seal: %s/%s has a seal that is not hex\n", bucket, key);
    return -1;
  }

  if (s3seal_fromHex(got.header("x-amz-meta-nonce"), into->prefix,
                     S3SEAL_NONCE_PREFIX) != S3SEAL_NONCE_PREFIX) {
    fprintf(stderr, "s3seal: %s/%s has a nonce that is not hex\n", bucket, key);
    return -1;
  }

  if (self->master->unwrap(blob, bound, into->key) != 0) {
    fprintf(stderr, "s3seal: %s/%s will not unwrap under this seed\n", bucket,
            key);
    return -1;
  }

  into->how.plain = strtoull(got.header("x-amz-meta-plain"), NULL, 10);
  into->how.partSize = strtoull(got.header("x-amz-meta-part"), NULL, 10);

  snprintf(into->etag, sizeof into->etag, "%.63s",
           got.header("x-amz-meta-etag"));

  /**
   * What was written down against what the length says it must be. They can
   * only differ if somebody edited one of them, and finding that out here is
   * cheaper than finding it out as a frame that will not open.
   */
  {
    int ok = 0;
    unsigned long long derived = s3seal_plainSize(into->stored, &ok);

    if (!ok || derived != into->how.plain) {
      fprintf(stderr,
              "s3seal: %s/%s says %llu plain but %llu stored works out to "
              "%llu\n",
              bucket, key, into->how.plain, into->stored, derived);
      return -1;
    }
  }

  worst = 0;

  return worst;
}

/* ------------------------------------------------------------------- put */

int s3seal_proxy_t.put(s3seal_proxy_t *self, const char *bucket,
                       const char *key, const char *mime, const void *body,
                       size_t length, char *etag, size_t room) {

  char url[S3SEAL_URL_MAX];
  char *bound = s3seal_join(bucket, "/", key);
  unsigned char dataKey[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
  unsigned char blob[S3SEAL_BLOB];
  char sealHex[S3SEAL_BLOB * 2 + 1];
  char nonceHex[S3SEAL_NONCE_PREFIX * 2 + 1];
  char plainText[32];
  char digest[33];
  unsigned char *sealed;
  unsigned long long wrote = 0;
  fetch_answer_t put;
  int worst = -1;

  if (bound == NULL ||
      s3seal_urlFor(self->config->upstream, bucket, key, url, sizeof url) != 0) {
    free(bound);
    return -1;
  }

  defer free(bound);

  if (s3seal_timing < 0)
    s3seal_timing = getenv("S3SEAL_TIMING") != NULL;

  {
    double began = s3seal_clock();
    double afterDigest;
    double afterSeal;
    double afterPut;

  /* the ETag is the plaintext's, and it is taken before anything is sealed */
  s3seal_md5Hex(body, length, digest);
  snprintf(etag, room, "\"%s\"", digest);

  afterDigest = s3seal_clock();

  if (s3seal_random(dataKey, S3SEAL_KEY) != 0 ||
      s3seal_random(prefix, S3SEAL_NONCE_PREFIX) != 0)
    return -1;

  defer memset(dataKey, 0, S3SEAL_KEY);

  sealed = malloc((size_t)s3seal_sealedSize(length) + 1);

  if (sealed == NULL)
    return -1;

  defer free(sealed);

  if (s3seal_seal(dataKey, prefix, 0, 1, body, length, sealed, &wrote) != 0 ||
      self->master->wrap(dataKey, bound, blob) != 0)
    return -1;

  afterSeal = s3seal_clock();

  s3seal_toHex(blob, sizeof blob, sealHex);
  s3seal_toHex(prefix, S3SEAL_NONCE_PREFIX, nonceHex);
  snprintf(plainText, sizeof plainText, "%llu", (unsigned long long)length);

  put = call(self, "PUT", url)
            .header("x-amz-meta-seal", sealHex)
            .header("x-amz-meta-nonce", nonceHex)
            .header("x-amz-meta-plain", plainText)
            .header("x-amz-meta-part", "0")
            .header("x-amz-meta-etag", etag)
            .header("content-type", mime != NULL && mime[0] != 0
                                        ? mime
                                        : "binary/octet-stream")
            .bytes(sealed, (size_t)wrote)
            .send();

  defer put.release();

  afterPut = s3seal_clock();

  if (s3seal_timing)
    fprintf(stderr,
            "s3seal: put %llu bytes - md5 %.0f ms, seal %.0f ms, "
            "upstream %.0f ms, total %.0f ms\n",
            (unsigned long long)length, afterDigest - began,
            afterSeal - afterDigest, afterPut - afterSeal, afterPut - began);

  worst = put.ok ? 0 : -1;

  if (!put.ok)
    fprintf(stderr, "s3seal: upstream refused PUT %s/%s: %d %.400s\n", bucket,
            key, put.status, put.failed ? put.why : put.text());

  return worst;
  }
}

/* ------------------------------------------------------------------- get */

/**
 * Opening happens as the bytes land, one frame at a time.
 *
 * The sealed body is never whole anywhere: what is held is the tail of a
 * frame that has not finished arriving, and that is `S3SEAL_FRAME` plus its
 * header - sixty-five kilobytes, whatever the object weighs.
 */
typedef struct {
  const s3seal_seal_t *what;

  unsigned char pending[S3SEAL_FRAME + S3SEAL_OVERHEAD];
  size_t fill;

  unsigned long long frame;

  /** How much of the first frame to throw away, and how much is wanted. */
  unsigned long long skip;
  unsigned long long left;

  fetch_sink_t sink;
  void *with;

  int broke;
} s3seal_opening_t;

static size_t opening(void *raw, const void *bytes, size_t length) {

  s3seal_opening_t *how = raw;
  const unsigned char *at = bytes;
  size_t took = length;

  while (length > 0 && !how->broke) {

    size_t stride = S3SEAL_FRAME + S3SEAL_OVERHEAD;
    size_t room = stride - how->fill;
    size_t piece = length < room ? length : room;
    unsigned char opened[S3SEAL_FRAME];
    unsigned long long got = 0;

    memcpy(how->pending + how->fill, at, piece);

    how->fill += piece;
    at += piece;
    length -= piece;

    /**
     * A frame is opened when it is whole, and the last one of a range is
     * short - so the end of the fetch is what says it is whole rather than
     * its length. That is what `left` is counted down for.
     */
    if (how->fill < stride && length == 0 && how->left > 0)
      break;

    if (how->fill < stride)
      break;

    if (s3seal_open(how->what->key, how->what->prefix, &how->what->how,
                    how->frame, how->pending, how->fill, opened, &got) != 0) {
      how->broke = 1;
      return 0;
    }

    ++how->frame;
    how->fill = 0;

    {
      unsigned long long from = how->skip < got ? how->skip : got;
      unsigned long long give = got - from;

      how->skip -= from;

      if (give > how->left)
        give = how->left;

      if (give > 0 && how->sink(how->with, opened + from, (size_t)give) !=
                          (size_t)give) {
        how->broke = 1;
        return 0;
      }

      how->left -= give;
    }
  }

  return took;
}

/** Whatever is left in the buffer when the fetch ends is the last frame. */
static int finishOpening(s3seal_opening_t *how) {

  unsigned char opened[S3SEAL_FRAME];
  unsigned long long got = 0;

  if (how->broke)
    return -1;

  if (how->fill == 0)
    return 0;

  if (s3seal_open(how->what->key, how->what->prefix, &how->what->how,
                  how->frame, how->pending, how->fill, opened, &got) != 0)
    return -1;

  {
    unsigned long long from = how->skip < got ? how->skip : got;
    unsigned long long give = got - from;

    if (give > how->left)
      give = how->left;

    if (give > 0 &&
        how->sink(how->with, opened + from, (size_t)give) != (size_t)give)
      return -1;

    how->left -= give;
  }

  return 0;
}

int s3seal_proxy_t.get(s3seal_proxy_t *self, const char *bucket,
                       const char *key, const s3seal_seal_t *what,
                       unsigned long long at, unsigned long long want,
                       fetch_sink_t sink, void *with) {

  char url[S3SEAL_URL_MAX];
  char range[64];
  unsigned long long from;
  unsigned long long length;
  unsigned long long skip;
  unsigned long long first;
  s3seal_opening_t how;
  fetch_answer_t got;
  int worst;

  if (s3seal_urlFor(self->config->upstream, bucket, key, url, sizeof url) != 0)
    return -1;

  s3seal_span(at, want, what->how.plain, &from, &length, &skip, &first);

  if (want > what->how.plain - at)
    want = what->how.plain - at;

  memset(&how, 0, sizeof how);

  how.what = what;
  how.frame = first;
  how.skip = skip;
  how.left = want;
  how.sink = sink;
  how.with = with;

  snprintf(range, sizeof range, "bytes=%llu-%llu", from,
           from + length - (length > 0 ? 1 : 0));

  got = call(self, "GET", url)
            .header("range", range)
            .drain(opening, &how)
            .send();

  defer got.release();

  worst = got.ok && finishOpening(&how) == 0 && !how.broke ? 0 : -1;

  if (worst != 0)
    fprintf(stderr, "s3seal: could not open %s/%s: upstream %d\n", bucket, key,
            got.failed ? 502 : got.status);

  return worst;
}

/* ------------------------------------------------------------------ pass */

int s3seal_proxy_t.pass(s3seal_proxy_t *self, const char *method,
                        const char *bucket, const char *key,
                        const char *query, fetch_answer_t *into) {

  char url[S3SEAL_URL_MAX];

  if (s3seal_urlFor(self->config->upstream, bucket, key, url, sizeof url) != 0)
    return -1;

  if (query != NULL && query[0] != 0) {
    size_t used = strlen(url);
    snprintf(url + used, sizeof url - used, "?%s", query);
  }

  *into = call(self, method, url).send();

  return into->failed ? -1 : 0;
}

/* ========================================================================= */
/*                               multipart                                   */
/* ========================================================================= */

/** Where an upload's own little object lives. */
static void initKey(s3seal_proxy_t *self, const char *id, char *into,
                    size_t room) {

  snprintf(into, room, "%s/%s.init", self->config->scratch, id);
}

/** And where its parts do. */
static void partKey(s3seal_proxy_t *self, const char *id, int number,
                    unsigned long long length, const char *digest, char *into,
                    size_t room) {

  /**
   * The number is padded, so a plain lexicographic listing comes back in part
   * order and nothing has to sort it. The length and the digest ride along
   * because the completion needs both and a listing is one request where a
   * HEAD of every part is ten thousand.
   */
  snprintf(into, room, "%s/%s/%05d.%llu.%s", self->config->scratch, id,
           number, length, digest);
}

int s3seal_proxy_t.begin(s3seal_proxy_t *self, const char *bucket,
                         const char *key, const char *mime, char *id,
                         size_t room) {

  unsigned char raw[16];
  unsigned char dataKey[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
  unsigned char blob[S3SEAL_BLOB];
  char sealHex[S3SEAL_BLOB * 2 + 1];
  char nonceHex[S3SEAL_NONCE_PREFIX * 2 + 1];
  char where[S3SEAL_KEY_MAX];
  char url[S3SEAL_URL_MAX];
  char *bound = s3seal_join(bucket, "/", key);
  fetch_answer_t put;

  if (bound == NULL)
    return -1;

  defer free(bound);

  if (s3seal_random(raw, sizeof raw) != 0 ||
      s3seal_random(dataKey, S3SEAL_KEY) != 0 ||
      s3seal_random(prefix, S3SEAL_NONCE_PREFIX) != 0)
    return -1;

  defer memset(dataKey, 0, S3SEAL_KEY);

  s3seal_toHex(raw, sizeof raw, id);

  /**
   * The key is wrapped against the object's final name, not against the
   * upload's id. So a part parked under one upload cannot be completed into
   * a different key by anybody who can rename things on the upstream.
   */
  if (self->master->wrap(dataKey, bound, blob) != 0)
    return -1;

  s3seal_toHex(blob, sizeof blob, sealHex);
  s3seal_toHex(prefix, S3SEAL_NONCE_PREFIX, nonceHex);

  initKey(self, id, where, sizeof where);

  if (s3seal_urlFor(self->config->upstream, bucket, where, url, sizeof url) !=
      0)
    return -1;

  put = call(self, "PUT", url)
            .header("x-amz-meta-seal", sealHex)
            .header("x-amz-meta-nonce", nonceHex)
            .header("x-amz-meta-key", key)
            .header("x-amz-meta-mime",
                    mime != NULL && mime[0] != 0 ? mime
                                                 : "binary/octet-stream")
            .bytes("", 0)
            .send();

  defer put.release();

  if (!put.ok)
    fprintf(stderr, "s3seal: parking the upload key at %s failed: %d %s\n",
            where, put.status, put.failed ? put.why : put.text());

  return put.ok ? 0 : -1;
}

int s3seal_proxy_t.upload(s3seal_proxy_t *self, const char *bucket,
                          const char *id, s3seal_upload_t *into) {

  char where[S3SEAL_KEY_MAX];
  char url[S3SEAL_URL_MAX];
  unsigned char blob[S3SEAL_BLOB];
  char *bound;
  fetch_answer_t got;
  int worst = -1;

  memset(into, 0, sizeof *into);

  initKey(self, id, where, sizeof where);

  snprintf(into->bucket, sizeof into->bucket, "%s", bucket);

  if (s3seal_urlFor(self->config->upstream, into->bucket, where, url,
                    sizeof url) != 0)
    return -1;

  got = call(self, "HEAD", url).nobody().send();

  defer got.release();

  if (!got.ok) {
    fprintf(stderr, "s3seal: reading the upload key at %s: %d %s\n", where,
            got.status, got.failed ? got.why : "");
    return -1;
  }

  snprintf(into->key, sizeof into->key, "%.1023s",
           got.header("x-amz-meta-key"));
  snprintf(into->mime, sizeof into->mime, "%.127s",
           got.header("x-amz-meta-mime"));

  bound = s3seal_join(into->bucket, "/", into->key);

  if (bound == NULL)
    return -1;

  defer free(bound);

  if (s3seal_fromHex(got.header("x-amz-meta-seal"), blob, sizeof blob) !=
          (int)sizeof blob ||
      s3seal_fromHex(got.header("x-amz-meta-nonce"), into->prefix,
                     S3SEAL_NONCE_PREFIX) != S3SEAL_NONCE_PREFIX ||
      self->master->unwrap(blob, bound, into->dataKey) != 0) {
    fprintf(stderr, "s3seal: the upload key at %s will not read back "
                    "(key '%s', seal %zu chars)\n",
            where, into->key, strlen(got.header("x-amz-meta-seal")));
    return -1;
  }

  worst = 0;

  return worst;
}

int s3seal_proxy_t.part(s3seal_proxy_t *self, const char *id,
                        const s3seal_upload_t *what, int number,
                        const void *body, size_t length, char *etag,
                        size_t room) {

  char digest[33];
  char where[S3SEAL_KEY_MAX];
  char url[S3SEAL_URL_MAX];
  unsigned char *sealed;
  unsigned long long wrote = 0;
  fetch_answer_t put;

  s3seal_md5Hex(body, length, digest);
  snprintf(etag, room, "\"%s\"", digest);

  sealed = malloc((size_t)s3seal_sealedSize(length) + 1);

  if (sealed == NULL)
    return -1;

  defer free(sealed);

  /**
   * `1` for last, and it means the last frame *of this part*. Whether this
   * part is the object's last one is not known here and does not need to be -
   * see frame.h, where the bit's meaning is written down.
   */
  if (s3seal_seal(what->dataKey, what->prefix, (unsigned int)number, 1, body,
                  length, sealed, &wrote) != 0)
    return -1;

  partKey(self, id, number, (unsigned long long)length, digest, where,
          sizeof where);

  if (s3seal_urlFor(self->config->upstream, what->bucket, where, url,
                    sizeof url) != 0)
    return -1;

  put = call(self, "PUT", url).bytes(sealed, (size_t)wrote).send();

  defer put.release();

  return put.ok ? 0 : -1;
}

/** One parked part, as the listing named it. */
typedef struct {
  int number;
  unsigned long long length;
  char digest[33];
  char key[S3SEAL_KEY_MAX];
} s3seal_parked_t;

/**
 * Every parked part of one upload, in part order.
 *
 * One `ListObjectsV2`, and the names carry what would otherwise be a HEAD
 * each. The padding in the name is what makes the upstream's own ordering
 * the right one.
 */
static int parkedParts(s3seal_proxy_t *self, const char *id,
                       const char *bucket, s3seal_parked_t *into, int room,
                       int *count) {

  char url[S3SEAL_URL_MAX];
  char prefix[S3SEAL_KEY_MAX];
  fetch_answer_t got;
  const char *at;

  *count = 0;

  snprintf(prefix, sizeof prefix, "%s/%s/", self->config->scratch, id);

  if (s3seal_urlFor(self->config->upstream, bucket, NULL, url, sizeof url) !=
      0)
    return -1;

  got = call(self, "GET", url)
            .query("list-type", "2")
            .query("prefix", prefix)
            .query("max-keys", "10000")
            .send();

  defer got.release();

  if (!got.ok)
    return -1;

  at = got.body != NULL ? got.body : "";

  while (*count < room) {

    const char *open = strstr(at, "<Key>");
    const char *shut;
    const char *name;
    char one[S3SEAL_KEY_MAX];
    size_t length;

    if (open == NULL)
      break;

    open += 5;
    shut = strstr(open, "</Key>");

    if (shut == NULL)
      break;

    length = (size_t)(shut - open);

    if (length >= sizeof one) {
      at = shut;
      continue;
    }

    memcpy(one, open, length);
    one[length] = 0;

    at = shut;

    name = strrchr(one, '/');
    name = name != NULL ? name + 1 : one;

    if (sscanf(name, "%d.%llu.%32s", &into[*count].number,
               &into[*count].length, into[*count].digest) != 3)
      continue;

    snprintf(into[*count].key, sizeof into[*count].key, "%s", one);

    ++*count;
  }

  return 0;
}

int s3seal_proxy_t.finish(s3seal_proxy_t *self, const char *id,
                          const s3seal_upload_t *what, char *etag,
                          size_t room) {

  s3seal_parked_t *parts = calloc(S3SEAL_PARTS_MAX, sizeof *parts);
  unsigned char *digests;
  unsigned char rolled[16];
  char rolledHex[33];
  char url[S3SEAL_URL_MAX];
  char sealHex[S3SEAL_BLOB * 2 + 1];
  char nonceHex[S3SEAL_NONCE_PREFIX * 2 + 1];
  char plainText[32];
  char partText[32];
  unsigned char blob[S3SEAL_BLOB];
  char *bound = s3seal_join(what->bucket, "/", what->key);
  char upstreamId[256] = "";
  unsigned long long plain = 0;
  unsigned long long partSize = 0;
  s3seal_buf_t done = {0};
  int count = 0;
  int worst = -1;

  if (parts == NULL || bound == NULL) {
    free(parts);
    free(bound);
    return -1;
  }

  defer free(parts);
  defer free(bound);
  defer done.drop();

  if (parkedParts(self, id, what->bucket, parts, S3SEAL_PARTS_MAX, &count) !=
          0 ||
      count == 0)
    return -1;

  digests = malloc((size_t)count * 16);

  if (digests == NULL)
    return -1;

  defer free(digests);

  /**
   * The parts have to be the same size but for the last, and it is not a
   * preference: the layout that lets a reader work out which `(part, frame)`
   * belongs at an offset is one number, and one number can only describe
   * uniform parts. A client that does otherwise is told so rather than
   * handed an object that will not open.
   */
  partSize = parts[0].length;

  /**
   * One part is a single PUT wearing a different hat, so it is recorded as
   * one - `partSize` of zero - and the frame alignment below does not apply
   * to it. Its frames are numbered from zero straight through, which is what
   * `placeOf` does for a body that arrived in one piece.
   */
  if (count == 1)
    partSize = 0;

  if (partSize != 0 && partSize % S3SEAL_FRAME != 0) {
    fprintf(stderr,
            "s3seal: a part size of %llu is not a whole number of %d byte "
            "frames - set the client's chunk size to a multiple of it\n",
            partSize, S3SEAL_FRAME);
    return -1;
  }

  for (int at = 0; at < count; ++at) {

    /* every part but the last has to be the same size, which is what makes
       one number enough to say where a frame belongs */
    if (at + 1 < count && parts[at].length != parts[0].length) {
      fprintf(stderr,
              "s3seal: part %d is %llu bytes where the first was %llu - "
              "s3seal needs a uniform part size\n",
              parts[at].number, parts[at].length, parts[0].length);
      return -1;
    }

    plain += parts[at].length;

    s3seal_fromHex(parts[at].digest, digests + at * 16, 16);
  }

  /* the multipart ETag S3 defines: the MD5 of the parts' MD5s, and the count */
  s3seal_md5(digests, (size_t)count * 16, rolled);
  s3seal_toHex(rolled, sizeof rolled, rolledHex);
  snprintf(etag, room, "\"%s-%d\"", rolledHex, count);

  if (self->master->wrap(what->dataKey, bound, blob) != 0)
    return -1;

  s3seal_toHex(blob, sizeof blob, sealHex);
  s3seal_toHex(what->prefix, S3SEAL_NONCE_PREFIX, nonceHex);
  snprintf(plainText, sizeof plainText, "%llu", plain);
  snprintf(partText, sizeof partText, "%llu", partSize);

  if (s3seal_urlFor(self->config->upstream, what->bucket, what->key, url,
                    sizeof url) != 0)
    return -1;

  /* ---------------------------------------------- our own upload, upstream */

  {
    fetch_answer_t began = call(self, "POST", url)
                               .query("uploads", "")
                               .header("x-amz-meta-seal", sealHex)
                               .header("x-amz-meta-nonce", nonceHex)
                               .header("x-amz-meta-plain", plainText)
                               .header("x-amz-meta-part", partText)
                               .header("x-amz-meta-etag", etag)
                               .header("content-type", what->mime)
                               .bytes("", 0)
                               .send();

    const char *open;

    defer began.release();

    if (!began.ok)
      return -1;

    open = began.body != NULL ? strstr(began.body, "<UploadId>") : NULL;

    if (open != NULL) {

      const char *shut = strstr(open + 10, "</UploadId>");

      if (shut != NULL && (size_t)(shut - open - 10) < sizeof upstreamId) {
        memcpy(upstreamId, open + 10, (size_t)(shut - open - 10));
        upstreamId[shut - open - 10] = 0;
      }
    }

    if (upstreamId[0] == 0)
      return -1;
  }

  /* ------------------------------------- the parts, copied server side */

  done.add("<CompleteMultipartUpload>");

  for (int at = 0; at < count; ++at) {

    char source[S3SEAL_KEY_MAX * 2];
    char number[16];
    fetch_answer_t copied;
    const char *tag;
    const char *shut;

    snprintf(source, sizeof source, "/%s/%s", what->bucket, parts[at].key);
    snprintf(number, sizeof number, "%d", parts[at].number);

    copied = call(self, "PUT", url)
                 .query("partNumber", number)
                 .query("uploadId", upstreamId)
                 .header("x-amz-copy-source", source)
                 .send();

    if (!copied.ok) {
      copied.release();
      return -1;
    }

    tag = copied.body != NULL ? strstr(copied.body, "<ETag>") : NULL;
    shut = tag != NULL ? strstr(tag + 6, "</ETag>") : NULL;

    done.addf("<Part><PartNumber>%d</PartNumber><ETag>", parts[at].number);

    if (tag != NULL && shut != NULL)
      done.addn(tag + 6, (size_t)(shut - tag - 6));

    done.add("</ETag></Part>");

    copied.release();
  }

  done.add("</CompleteMultipartUpload>");

  if (done.broke)
    return -1;

  {
    fetch_answer_t ended = call(self, "POST", url)
                               .query("uploadId", upstreamId)
                               .header("content-type", "application/xml")
                               .bytes(done.at, done.count)
                               .send();

    defer ended.release();

    /* S3 answers 200 with an error document, so the body has to be read */
    if (!ended.ok ||
        (ended.body != NULL && strstr(ended.body, "<Error") != NULL))
      return -1;
  }

  self->abort(what->bucket, id);

  worst = 0;

  return worst;
}

void s3seal_proxy_t.abort(s3seal_proxy_t *self, const char *bucket,
                          const char *id) {

  s3seal_parked_t *parts = calloc(S3SEAL_PARTS_MAX, sizeof *parts);
  char where[S3SEAL_KEY_MAX];
  char url[S3SEAL_URL_MAX];
  int count = 0;

  if (parts == NULL)
    return;

  defer free(parts);

  if (parkedParts(self, id, bucket, parts, S3SEAL_PARTS_MAX, &count) == 0)
    for (int at = 0; at < count; ++at)
      if (s3seal_urlFor(self->config->upstream, bucket, parts[at].key, url,
                        sizeof url) == 0) {

        fetch_answer_t gone = call(self, "DELETE", url).send();

        gone.release();
      }

  initKey(self, id, where, sizeof where);

  if (s3seal_urlFor(self->config->upstream, bucket, where, url, sizeof url) ==
      0) {

    fetch_answer_t gone = call(self, "DELETE", url).send();

    gone.release();
  }
}
