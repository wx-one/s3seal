#ifndef S3SEAL_FRAME_H
#define S3SEAL_FRAME_H

/**
 * The frame format, which is the whole argument of this project.
 *
 * ------------------------------------------------------------- the layout
 *
 * A body is cut into `S3SEAL_FRAME` pieces and each is sealed on its own:
 *
 *     [ part:4 | frame:4 | flags:1 ][ ciphertext ][ tag:16 ]
 *     \_________ 9 bytes __________/              \__ 16 __/
 *
 * The nine bytes in front are **plaintext and authenticated**: they go into
 * AES-GCM as associated data, so they can be read without a key and cannot be
 * changed with one. They are what makes the format self-locating.
 *
 * ---------------------------------------------- why the header is in there
 *
 * This is the part every other implementation gets stuck on, so it is worth
 * being precise about.
 *
 * A frame's nonce has to be unique under its key and its position has to be
 * bound, or frames can be reordered, dropped or replayed and every tag still
 * checks out. The obvious way is to derive both from the frame's index in the
 * object. That works when one writer sees the whole object in order.
 *
 * A proxy does not. `UploadPart` arrives with a part number, out of order,
 * possibly in parallel, and nobody knows how long the earlier parts are - so
 * the *global* index of a frame is unknowable at the moment it has to be
 * sealed. And after `CompleteMultipartUpload` the upstream has concatenated
 * everything and the reader has only the global index. The two sides never
 * have the same number.
 *
 * So the number is carried in the frame. The writer knows `(part, frame)`
 * because they are what it was handed. The reader reads them out of the
 * header, and derives the same nonce and the same associated data from them.
 * Neither side needs to know the layout of the object, which means the
 * layout does not have to be stored anywhere - and that is the sentence this
 * whole project exists to be able to say.
 *
 * `flags` carries one bit today, `S3SEAL_LAST`, and it marks the last frame
 * **of its part** - not of the object.
 *
 * That distinction is forced by multipart. A part is sealed when it arrives
 * and nobody knows then whether it is the final one; only the completion
 * knows, and by then the bytes are on the upstream. Marking the end of a part
 * is something the writer always knows, so that is what the bit says.
 *
 * Truncation is caught elsewhere and better: the stored length has to work
 * out to the plaintext length the metadata claims, which `headOf` checks
 * before a single frame is read. Dropping a whole part fails that arithmetic.
 *
 * ------------------------------------------------- and what the header is not
 *
 * The header binds a frame to *its place in its part*. It does not, on its
 * own, bind the part to its place in the object - two whole parts exchanged
 * carry their own honest headers, every tag verifies, and the body is wrong.
 * The first version of this file had exactly that hole and a test found it.
 *
 * So opening takes a `s3seal_layout_t`: how large a part is, which is one
 * number, and it comes out of the object's metadata that had to be read for
 * the key anyway. From it the reader works out which `(part, frame)` *ought*
 * to be at a given offset and refuses anything else. A part moved anywhere
 * is then a part whose header disagrees with where it is.
 *
 * That is why the format asks for parts that are a whole number of frames.
 * It is not an implementation convenience - it is what makes a position
 * checkable without storing a table of every part.
 *
 * ----------------------------------------------------------- the nonce
 *
 *     [ random:4 ][ part:4 ][ frame:4 ]
 *
 * The last eight bytes are unique within an object by construction. The four
 * in front come from the object's metadata and exist for the case the design
 * says cannot happen - two objects sharing a data key - so that a bug there
 * is a bad day rather than a broken cipher.
 *
 * ------------------------------------------------------- and the size
 *
 * Every full frame is exactly `S3SEAL_FRAME + S3SEAL_OVERHEAD` bytes on the
 * wire. A stride, not a table. So:
 *
 *     ciphertext length  ->  plaintext length     is arithmetic
 *     plaintext offset   ->  which bytes to fetch is arithmetic
 *
 * both directions, with nothing read and nothing stored. That is what lets
 * `ListObjectsV2` report true sizes over a thousand objects without touching
 * one of them, and what makes a range request a single ranged fetch upstream.
 */

#include "s3seal.h"

#include <stddef.h>

/** Fails only if the machine has no randomness, which is worth saying aloud. */
int s3seal_random(void *into, size_t length);

/* -------------------------------------------------------------- the sizes */

/** What `plain` bytes occupy once sealed. */
unsigned long long s3seal_sealedSize(unsigned long long plain);

/**
 * And back again - what a sealed object of `sealed` bytes holds.
 *
 * The inverse of the one above, and it has to be exact rather than close: it
 * is what a `HEAD` and a listing answer with. A length that is not a whole
 * number of frames plus a remainder is not one of ours, and answers zero
 * with `ok` cleared rather than a plausible number.
 */
unsigned long long s3seal_plainSize(unsigned long long sealed, int *ok);

/** How many frames a body of `plain` bytes is. */
unsigned long long s3seal_frames(unsigned long long plain);

/**
 * How an object was cut up, which is what makes a frame's place checkable.
 *
 * `partSize` is the plaintext each part holds - the same for every part but
 * the last, which is what S3 requires of an upload anyway - and zero for a
 * body that arrived in one PUT. It has to be a whole number of frames.
 *
 * Two numbers, both in the object's user metadata, both read in the same
 * request that fetches the key. No table, no side object, no database.
 */
typedef struct s3seal_layout_t {
  unsigned long long partSize;
  unsigned long long plain;
} s3seal_layout_t;

/** Which `(part, frame)` belongs at global frame `at`. */
void s3seal_placeOf(const s3seal_layout_t *how, unsigned long long at,
                    unsigned int *part, unsigned int *frame);

/** Whether global frame `at` is the last one of the part it belongs to. */
int s3seal_lastOf(const s3seal_layout_t *how, unsigned long long at);

/** Whether a part size can be checked against - a whole number of frames. */
int s3seal_layoutOk(const s3seal_layout_t *how);

/**
 * The sealed byte range that has to be fetched to answer a plaintext range.
 *
 * Whole frames, because a partial frame cannot be opened. The caller trims
 * the ends after opening; `skip` says by how much at the front.
 */
void s3seal_span(unsigned long long at, unsigned long long want,
                 unsigned long long plain, unsigned long long *from,
                 unsigned long long *length, unsigned long long *skip,
                 unsigned long long *firstFrame);

/* ------------------------------------------------------------- one frame */

/**
 * Seals one frame. `into` needs `length + S3SEAL_OVERHEAD` bytes.
 *
 * `part` is zero for a body that arrived in one piece, and the S3 part
 * number otherwise - so a single PUT and a one-part upload seal identically,
 * which is a property worth having when the two paths are compared.
 */
int s3seal_sealFrame(const unsigned char *key, const unsigned char *prefix,
                     unsigned int part, unsigned int frame, int last,
                     const void *plain, size_t length, unsigned char *into);

/**
 * Opens one. `into` needs `length - S3SEAL_OVERHEAD` bytes.
 *
 * `part` and `frame` come back as they were read out of the header, and the
 * caller is expected to check them against where it thinks it is. The tag
 * proves they were not changed; only the caller knows whether they are the
 * ones it asked for, and a frame from elsewhere in the same object would
 * otherwise open cleanly.
 */
int s3seal_openFrame(const unsigned char *key, const unsigned char *prefix,
                     const void *sealed, size_t length, unsigned char *into,
                     size_t *plainLength, unsigned int *part,
                     unsigned int *frame, int *last);

/* ------------------------------------------------------ a whole body, once */

/**
 * Seals a body that is already in memory. `into` needs `s3seal_sealedSize`.
 *
 * `part` numbers every frame the same, which is what `UploadPart` wants: the
 * frames inside one part are numbered from zero within it.
 *
 * `last` says whether the final frame closes the *object* - false for every
 * part of a multipart upload except the one the client sends last, which the
 * completion is what actually knows. See upload.h for how that is settled.
 */
int s3seal_seal(const unsigned char *key, const unsigned char *prefix,
                unsigned int part, int last, const void *plain, size_t length,
                unsigned char *into, unsigned long long *sealedLength);

/**
 * Opens a run of whole frames, starting at global frame `firstFrame`.
 *
 * Every frame's header is checked against the place `how` says it should be
 * in. That check is not a formality and it is not the tag's job: a tag says
 * a frame is intact, and this says it is *here*.
 */
int s3seal_open(const unsigned char *key, const unsigned char *prefix,
                const s3seal_layout_t *how, unsigned long long firstFrame,
                const void *sealed, size_t length, unsigned char *into,
                unsigned long long *plainLength);

/* --------------------------------------------------------- the key itself */

/**
 * The key that wraps data keys, derived from one seed.
 *
 * HKDF-SHA256 over the seed with the object's `bucket/key` as info, so the
 * wrapping key differs per object and a blob lifted from one object's
 * metadata into another's does not open. The seed is the only secret the
 * operator holds.
 */
typedef struct s3seal_master_t {
  unsigned char seed[S3SEAL_KEY];
  int loaded;
} s3seal_master_t;

int s3seal_master_t.load(s3seal_master_t *self, const char *path);
int s3seal_master_t.make(s3seal_master_t *self, const char *path);

int s3seal_master_t.wrap(s3seal_master_t *self, const unsigned char *dataKey,
                         const char *bound, unsigned char *blob);

int s3seal_master_t.unwrap(s3seal_master_t *self, const unsigned char *blob,
                           const char *bound, unsigned char *dataKey);

/* -------------------------------------------------- the digests S3 asks for */

void s3seal_sha256(const void *bytes, size_t length, unsigned char *into);
void s3seal_sha256Hex(const void *bytes, size_t length, char *into);

void s3seal_hmacSha256(const void *key, size_t keyLength, const void *bytes,
                       size_t length, unsigned char *into);

/** An S3 ETag is the MD5 of the body in hex, and that is not a security claim. */
void s3seal_md5Hex(const void *bytes, size_t length, char *into);
void s3seal_md5(const void *bytes, size_t length, unsigned char *into);

#endif /* S3SEAL_FRAME_H */
