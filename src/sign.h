#ifndef S3SEAL_SIGN_H
#define S3SEAL_SIGN_H

/**
 * AWS Signature Version 4, the *producing* half.
 *
 * `sigv4.h` checks what a client sent us. This signs what we send onwards,
 * and the two are not the same job: verifying rebuilds a canonical request
 * out of somebody else's headers and hopes to agree, while signing builds
 * both the request and its canonical form and cannot disagree with itself.
 *
 * ---------------------------------------------------------------- the hook
 *
 * It is a `fetch_call_t` hook, which is what `meta_fetch`'s `.before` exists
 * for: a signature has to be taken after the URL and every header are final
 * and before the request goes, and that is the only moment the hook runs.
 *
 *     fetch_answer_t got = meta_fetch("PUT", url)
 *                            .header("x-amz-meta-seal", blob)
 *                            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
 *                            .from(fd, length)
 *                            .before(s3seal_sign, &upstream)
 *                            .send();
 *
 * Every header already on the call is signed if it is `host` or begins with
 * `x-amz-`, which is the minimum S3 insists on and the maximum anything here
 * needs. That is why the key blob travels as `x-amz-meta-seal`: putting it
 * there means it is covered by the signature for free.
 *
 * ------------------------------------------------------- and the body hash
 *
 * The caller sets `x-amz-content-sha256` and this signs whatever it says.
 * For a body held in memory that is its SHA-256; for one streaming off a
 * descriptor it is `UNSIGNED-PAYLOAD`, because hashing a body we have not
 * read yet would mean reading it twice - once to hash and once to send - and
 * a proxy that buffers an object to hash it is a proxy that cannot pass one
 * larger than memory.
 *
 * That is a real trade and it is stated rather than hidden: over TLS the body
 * is protected in flight regardless, and `UNSIGNED-PAYLOAD` is what AWS's own
 * SDKs send for streaming uploads.
 */

#include "s3seal.h"

#include <meta_fetch.h>

/** Who we are to the upstream. Never the client's credentials. */
typedef struct s3seal_signer_t {
  const char *access;
  const char *secret;
  const char *region;
  const char *service;
} s3seal_signer_t;

/** The `.before` hook. `with` is a `s3seal_signer_t *`. */
void s3seal_sign(void *with, fetch_call_t *call);

/**
 * A URL for one object on the upstream, with the key encoded as S3 wants it.
 *
 * Built here rather than by each caller because the encoding has to match
 * what the signature is taken over, byte for byte. Two places doing it is two
 * places to get `+` or a space wrong, and the failure is a 403 from the
 * upstream that says nothing about which of them it was.
 */
int s3seal_urlFor(const char *upstream, const char *bucket, const char *key,
                  char *into, size_t room);

/** The same, percent-encoding one path segment into a buffer. */
size_t s3seal_encodePath(const char *from, char *into, size_t room);

#endif /* S3SEAL_SIGN_H */
