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
#include <string.h>
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
static const char *held(http_request_t *req, const char *text) {

  char *into = req->scratch + req->scratchUsed;
  size_t room = (size_t)(META_HTTP_SCRATCH - req->scratchUsed);
  size_t length = strlen(text);

  if (length + 1 > room)
    return "";

  memcpy(into, text, length + 1);

  req->scratchUsed += (int)length + 1;

  return into;
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

static http_response_t putObject(http_request_t *req) {

  char key[S3SEAL_KEY_MAX + 1];
  char etag[S3SEAL_ETAG_MAX];
  const char *bucket = req.param("bucket");
  http_body_t body = req.readBody();

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
    fprintf(stderr, "s3seal: nginx handed over %llu bytes\n",
            (unsigned long long)body.length);

  if (s3seal_upstream.put(bucket, key, req.header("content-type"), body.bytes,
                          body.length, etag, sizeof etag) != 0)
    return problem(req, 502, "InternalError", "the upstream would not take it");

  return req.reply(200).header("ETag", etag).send();
}

/** What a reader thread was told to fetch. Its own, and it frees it. */
typedef struct {
  char bucket[S3SEAL_BUCKET_MAX + 1];
  char key[S3SEAL_KEY_MAX + 1];

  s3seal_seal_t what;

  unsigned long long at;
  unsigned long long want;

  int into;
} s3seal_pull_t;

/** Opened bytes into the pipe, whatever it takes. */
static size_t intoPipe(void *with, const void *bytes, size_t length) {

  const char *at = bytes;
  size_t done = 0;

  while (done < length) {

    ssize_t put = write(*(int *)with, at + done, length - done);

    if (put <= 0)
      return done;

    done += (size_t)put;
  }

  return done;
}

static void pullRun(s3seal_pull_t *job) {

  s3seal_upstream.get(job->bucket, job->key, &job->what, job->at, job->want,
                      intoPipe, &job->into);

  /* the close is what tells nginx the answer is finished, whether it went
     well or not - a client sees a short body, which is what a failed read of
     an already-started response can be */
  close(job->into);

  free(job);
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
    char *length = req->scratch + req->scratchUsed;
    char *range;
    http_response_t answer = req.reply(ranged ? 206 : 200);

    req->scratchUsed += 1 + snprintf(length,
                                     (size_t)(META_HTTP_SCRATCH -
                                              req->scratchUsed),
                                     "%llu", want);

    range = req->scratch + req->scratchUsed;

    answer = answer.header("ETag", held(req, what.etag))
                 .header("Content-Length", length)
                 .header("Accept-Ranges", "bytes")
                 .mime(held(req, what.mime[0] != 0
                                     ? what.mime
                                     : "binary/octet-stream"));

    if (what.when[0] != 0)
      answer = answer.header("Last-Modified", held(req, what.when));

    if (ranged) {
      req->scratchUsed +=
          1 + snprintf(range,
                       (size_t)(META_HTTP_SCRATCH - req->scratchUsed),
                       "bytes %llu-%llu/%llu", at,
                       at + (want > 0 ? want - 1 : 0), what.how.plain);
      answer = answer.header("Content-Range", range);
    }

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
 * progress are ours and not the bucket's.
 */
static http_response_t listing(http_request_t *req, fetch_answer_t *got) {

  s3seal_buf_t *out = &s3seal_answer;
  const char *at = got->body != NULL ? got->body : "";

  out->count = 0;
  out->broke = 0;

  while (*at != 0) {

    const char *size = strstr(at, "<Size>");
    const char *stop;
    unsigned long long stored;
    int ok = 0;

    if (size == NULL) {
      out->add(at);
      break;
    }

    stop = strstr(size, "</Size>");

    if (stop == NULL) {
      out->add(at);
      break;
    }

    out->addn(at, (size_t)(size - at));
    out->add("<Size>");

    stored = strtoull(size + 6, NULL, 10);

    out->addf("%llu", s3seal_plainSize(stored, &ok));

    at = stop;
  }

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

  meta_fetchDone();
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
