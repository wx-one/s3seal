#ifndef S3SEAL_S3_H
#define S3SEAL_S3_H

/**
 * The S3 surface, which is mostly somebody else's.
 *
 *   PUT    /:bucket/*key     seal it and store it upstream
 *   GET    /:bucket/*key     fetch it, open it, answer - whole or a range
 *   HEAD   /:bucket/*key     its metadata, with the plaintext length and ETag
 *   DELETE /:bucket/*key     straight through
 *   GET    /:bucket          a listing, with the sizes corrected
 *   PUT    /:bucket          make one
 *   DELETE /:bucket          remove one
 *   GET    /                 list buckets
 *
 * Everything a client sends is verified against *our* credentials and
 * everything we send is signed with the upstream's. The two never meet, which
 * is the whole reason a proxy is a useful place to encrypt.
 */

int s3seal_configure(void);
int s3seal_start(void);
void s3seal_stop(void);
void s3seal_routes(void);

#endif /* S3SEAL_S3_H */
