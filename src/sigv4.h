#ifndef S3SEAL_SIGV4_H
#define S3SEAL_SIGV4_H

/**
 * AWS Signature Version 4, the verifying half.
 *
 * ------------------------------------------------------------------- why
 *
 * Not because AWS compatibility is a goal in itself, but because it is what
 * makes every S3 client that already exists work against LTOS3 without being
 * touched - `aws s3 cp`, `rclone`, `mc`, boto3. A token of our own would mean
 * a client of our own.
 *
 * And it is what makes a redirect work. When a master node answers `307` with
 * another node's address, the client signs *again* for the host it is sent
 * to. Nothing is forwarded, nothing is proxied, and the second node checks
 * the second signature itself - which it can, because the nodes share the
 * credentials file and nothing else.
 *
 * ---------------------------------------------------------- what is checked
 *
 * The signature, and the clock. The clock because a signature that never
 * expires is a signature somebody can replay for a year; fifteen minutes is
 * what AWS allows and what every client already sends a date for.
 *
 * ---------------------------------------------------- what is not checked
 *
 * The per-chunk signatures of `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`. The seed
 * signature over the request is checked, the chunk framing is read, and each
 * chunk's own signature is skipped. That is stated rather than hidden: it
 * means a body could in principle be altered in flight by somebody who could
 * already alter it, on a connection that should have been TLS.
 */

#include "config.h"
#include "frame.h"

#include <meta_http.h>

typedef enum s3sealAuth : unsigned char {
  S3SEAL_AUTH_OK "ok",
  S3SEAL_AUTH_MISSING "no credentials",
  S3SEAL_AUTH_MALFORMED "malformed authorization header",
  S3SEAL_AUTH_UNKNOWN_KEY "unknown access key",
  S3SEAL_AUTH_BAD_SIGNATURE "signature does not match",
  S3SEAL_AUTH_SKEWED "the request date is too far from ours"
} s3seal_auth_t;

/** How the body was framed, which decides what has to be done to it. */
typedef enum s3sealPayload : unsigned char {
  S3SEAL_PAYLOAD_HASHED "hashed",
  S3SEAL_PAYLOAD_UNSIGNED "unsigned",
  S3SEAL_PAYLOAD_CHUNKED "aws-chunked"
} s3seal_payload_t;

typedef struct s3seal_signature_t {
  char access[128];
  char day[16];
  char region[80];
  char service[32];
  char signedHeaders[1024];
  char signature[96];
  char amzDate[32];
  char bodyHash[96];

  enum s3sealPayload payload;
} s3seal_signature_t;

/** Reads the `Authorization` header apart. */
s3seal_auth_t s3seal_signature_t.read(s3seal_signature_t *self,
                                    http_request_t *req);

/**
 * The whole check: the header apart, the canonical request rebuilt, the
 * signature recomputed, the clock compared.
 *
 * `who` comes back as the access key that signed it, for a log line.
 */
s3seal_auth_t s3seal_verify(s3seal_config_t *config, http_request_t *req,
                          char *who, size_t room);

/**
 * Unwraps `aws-chunked` framing in place and says how much is left.
 *
 * In place because the plain bytes are always shorter than the framed ones,
 * so there is nowhere else they need to go, and a second buffer the size of a
 * part is a second buffer the size of a part.
 */
int, size_t s3seal_dechunk(char *body, size_t length);

#endif /* S3SEAL_SIGV4_H */
