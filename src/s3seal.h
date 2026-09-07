#ifndef S3SEAL_H
#define S3SEAL_H

/**
 * s3seal - an S3 proxy that encrypts, and still tells the truth about it.
 *
 * =========================================================================
 * What the field gets wrong, and why
 * =========================================================================
 *
 * Three open projects encrypt in front of S3, and all three give something
 * up at the same place:
 *
 *   Intrinsec/s3proxy        seals the whole body as one AEAD blob, so
 *                            multipart is refused outright and a range
 *                            request has to fetch the whole object.
 *
 *   s3-encryption-gateway    frames properly and serves ranges, but lets
 *                            multipart through *unencrypted*, because the
 *                            upstream concatenates the parts server-side and
 *                            the frames stop lining up.
 *
 *   rclone crypt + serve s3  frames properly, ranges and multipart both
 *                            work and are encrypted - but stores no hash, so
 *                            the ETag it hands back is not the object's MD5.
 *
 * You can have two of {transparent proxy, real encryption, correct ETag}.
 * The third costs a place to keep metadata, and a proxy is not supposed to
 * have one.
 *
 * This one takes all three, and the whole design is one answer repeated: put
 * the metadata **on the upstream S3 itself**, where it costs no database, no
 * second system to keep consistent, and nothing to lose.
 *
 * =========================================================================
 * How
 * =========================================================================
 *
 * **The body is framed** - fixed-size pieces, each sealed on its own with its
 * own tag - so a range is a range and a part is a whole number of frames.
 * See frame.h, which is where the format is written down.
 *
 * **The size needs no metadata at all.** A frame is a fixed stride on the
 * wire, so the plaintext length is arithmetic from the ciphertext length and
 * back. That is what makes `ListObjectsV2` answer honestly without reading a
 * single object.
 *
 * **The key goes in `x-amz-meta-`.** Wrapped, and settable at the moment the
 * object is created - including at `CreateMultipartUpload`, where S3 carries
 * user metadata through to the finished object.
 *
 * **The ETag is the one that cannot be stored that way**, because it is the
 * one value S3 computes itself and will not be told, and because it is only
 * known once the last part has arrived. So multipart is not passed through:
 * parts are sealed into objects of their own under a reserved prefix, and the
 * completion assembles them into the real key with `UploadPartCopy` - server
 * side, no bytes back through us - at which point every part's plaintext MD5
 * is known and the object can be created *with the right ETag in its
 * metadata from the start*.
 *
 * Which also makes each part's own ETag right, and nothing else in the field
 * does that either.
 */

#include <stddef.h>

/**
 * Limits, as an enum rather than as `#define`.
 *
 * The same reason as in LTOS3: a `#define` does not survive lowering into
 * something a debugger or a report can name, and these are numbers that get
 * argued about later.
 */
enum s3sealLimit {
  /**
   * The plaintext in one frame.
   *
   * 64 KiB, and the size is a compromise with a name on each side. Larger
   * frames waste less on headers and read whole; smaller ones make a range
   * request cheaper, because the smallest thing that can be fetched and
   * opened is one frame.
   *
   * 64 KiB is also what minio's DARE and rclone's crypt both chose, and
   * there is a second reason for it here that neither of them has: a
   * multipart part has to be a whole number of frames or the frames stop
   * being a fixed stride, and every part size a real client picks - 5 MiB,
   * 8 MiB, 16 MiB - is a multiple of 64 KiB. At 1 MiB frames that is still
   * true; at 4 MiB it starts not to be.
   */
  S3SEAL_FRAME = 65536,

  /** AES-256. */
  S3SEAL_KEY = 32,

  /** GCM's, and the standard's, and the only one worth using. */
  S3SEAL_NONCE = 12,
  S3SEAL_TAG = 16,

  /** The part of the nonce that is random rather than counted. */
  S3SEAL_NONCE_PREFIX = 4,

  /** `[part:4][frame:4][flags:1]`, in front of every frame. */
  S3SEAL_HEAD = 9,

  /** What one frame costs on the wire beyond its plaintext. */
  S3SEAL_OVERHEAD = 25,

  /** A wrapped data key: nonce, key, tag. */
  S3SEAL_BLOB = 60,

  S3SEAL_KEY_MAX = 1024,
  S3SEAL_BUCKET_MAX = 63,
  S3SEAL_ETAG_MAX = 64,
  S3SEAL_UPLOADID_MAX = 64,
  S3SEAL_URL_MAX = 2048,

  /** S3's own ceiling on parts in one upload. */
  S3SEAL_PARTS_MAX = 10000
};

/** Set in a frame's flags when it is the last one of the object. */
enum s3sealFlag { S3SEAL_LAST = 1 };

#endif /* S3SEAL_H */
