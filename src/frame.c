/**
 * The crypto, and the only unit that includes OpenSSL.
 *
 * `frame.h` names none of OpenSSL's types, so nothing else compiles against
 * them and nothing else can drift into depending on a particular one.
 */
#include "frame.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int s3seal_random(void *into, size_t length) {
  return RAND_bytes(into, (int)length) == 1 ? 0 : -1;
}

/* ---------------------------------------------------------------- the sizes */

unsigned long long s3seal_frames(unsigned long long plain) {

  if (plain == 0)
    return 0;

  return (plain + S3SEAL_FRAME - 1) / S3SEAL_FRAME;
}

unsigned long long s3seal_sealedSize(unsigned long long plain) {

  unsigned long long whole = plain / S3SEAL_FRAME;
  unsigned long long rest = plain % S3SEAL_FRAME;

  return whole * (S3SEAL_FRAME + S3SEAL_OVERHEAD) +
         (rest != 0 ? rest + S3SEAL_OVERHEAD : 0);
}

unsigned long long s3seal_plainSize(unsigned long long sealed, int *ok) {

  unsigned long long stride = S3SEAL_FRAME + S3SEAL_OVERHEAD;
  unsigned long long whole = sealed / stride;
  unsigned long long rest = sealed % stride;

  if (ok != NULL)
    *ok = 1;

  if (rest == 0)
    return whole * S3SEAL_FRAME;

  /**
   * A remainder has to be a header, a tag and at least one byte between them.
   * Anything else is not a body of ours - most likely an object that was
   * already in the bucket before the proxy was put in front of it - and the
   * honest answer is to say so rather than to report a length that looks
   * right and is not.
   */
  if (rest < S3SEAL_OVERHEAD + 1) {
    if (ok != NULL)
      *ok = 0;
    return 0;
  }

  return whole * S3SEAL_FRAME + (rest - S3SEAL_OVERHEAD);
}

int s3seal_layoutOk(const s3seal_layout_t *how) {

  if (how->partSize == 0)
    return 1;

  return how->partSize % S3SEAL_FRAME == 0;
}

void s3seal_placeOf(const s3seal_layout_t *how, unsigned long long at,
                    unsigned int *part, unsigned int *frame) {

  unsigned long long perPart;

  /**
   * A single PUT is part zero, numbered straight through. A multipart object
   * numbers its parts from one, the way S3 does, so the two cases cannot be
   * confused by a frame that has wandered between them.
   */
  if (how->partSize == 0) {
    *part = 0;
    *frame = (unsigned int)at;
    return;
  }

  perPart = how->partSize / S3SEAL_FRAME;

  *part = (unsigned int)(at / perPart) + 1;
  *frame = (unsigned int)(at % perPart);
}

int s3seal_lastOf(const s3seal_layout_t *how, unsigned long long at) {

  unsigned long long total = s3seal_frames(how->plain);
  unsigned long long perPart;

  /* the object's own last frame closes whatever part it is in */
  if (at + 1 >= total)
    return 1;

  if (how->partSize == 0)
    return 0;

  perPart = how->partSize / S3SEAL_FRAME;

  return perPart != 0 && (at % perPart) + 1 == perPart;
}

void s3seal_span(unsigned long long at, unsigned long long want,
                 unsigned long long plain, unsigned long long *from,
                 unsigned long long *length, unsigned long long *skip,
                 unsigned long long *firstFrame) {

  unsigned long long stride = S3SEAL_FRAME + S3SEAL_OVERHEAD;
  unsigned long long first;
  unsigned long long last;
  unsigned long long end;

  if (at > plain)
    at = plain;

  end = want > plain - at ? plain : at + want;

  first = at / S3SEAL_FRAME;

  /* the frame the last wanted byte lives in; an empty range takes none */
  last = end > at ? (end - 1) / S3SEAL_FRAME : first;

  *from = first * stride;
  *skip = at - first * S3SEAL_FRAME;
  *firstFrame = first;

  /**
   * Clipped against the object rather than computed from the frame count,
   * because the last frame is short and asking the upstream for bytes past
   * the end of an object is an error on some implementations and a silently
   * truncated answer on others.
   */
  {
    unsigned long long through = (last + 1) * S3SEAL_FRAME;
    unsigned long long whole = s3seal_sealedSize(through < plain ? through
                                                                : plain);

    *length = whole > *from ? whole - *from : 0;
  }
}

/* -------------------------------------------------------------- one frame */

/** `[random:4][part:4][frame:4]`, unique under one key by construction. */
static void nonceFor(const unsigned char *prefix, unsigned int part,
                     unsigned int frame, unsigned char *into) {

  memcpy(into, prefix, S3SEAL_NONCE_PREFIX);

  into[4] = (unsigned char)(part >> 24);
  into[5] = (unsigned char)(part >> 16);
  into[6] = (unsigned char)(part >> 8);
  into[7] = (unsigned char)part;

  into[8] = (unsigned char)(frame >> 24);
  into[9] = (unsigned char)(frame >> 16);
  into[10] = (unsigned char)(frame >> 8);
  into[11] = (unsigned char)frame;
}

static void headFor(unsigned int part, unsigned int frame, int last,
                    unsigned char *into) {

  into[0] = (unsigned char)(part >> 24);
  into[1] = (unsigned char)(part >> 16);
  into[2] = (unsigned char)(part >> 8);
  into[3] = (unsigned char)part;

  into[4] = (unsigned char)(frame >> 24);
  into[5] = (unsigned char)(frame >> 16);
  into[6] = (unsigned char)(frame >> 8);
  into[7] = (unsigned char)frame;

  into[8] = last ? (unsigned char)S3SEAL_LAST : 0;
}

static unsigned int wordAt(const unsigned char *from) {
  return ((unsigned int)from[0] << 24) | ((unsigned int)from[1] << 16) |
         ((unsigned int)from[2] << 8) | (unsigned int)from[3];
}

int s3seal_sealFrame(const unsigned char *key, const unsigned char *prefix,
                     unsigned int part, unsigned int frame, int last,
                     const void *plain, size_t length, unsigned char *into) {

  EVP_CIPHER_CTX *how = EVP_CIPHER_CTX_new();
  unsigned char nonce[S3SEAL_NONCE];
  int moved = 0;
  int answer = -1;

  if (how == NULL)
    return -1;

  defer EVP_CIPHER_CTX_free(how);

  if (length > S3SEAL_FRAME)
    return -1;

  headFor(part, frame, last, into);
  nonceFor(prefix, part, frame, nonce);

  if (EVP_EncryptInit_ex(how, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_IVLEN, S3SEAL_NONCE, NULL) !=
          1 ||
      EVP_EncryptInit_ex(how, NULL, NULL, key, nonce) != 1)
    return -1;

  /**
   * The header is associated data, not ciphertext.
   *
   * So it can be read by anything that can read the object - which is what
   * makes a frame self-locating - and cannot be altered by anything that
   * cannot forge the tag. A frame moved to another position keeps the header
   * that says where it belongs, and the caller notices.
   */
  if (EVP_EncryptUpdate(how, NULL, &moved, into, S3SEAL_HEAD) != 1)
    return -1;

  if (length != 0 &&
      EVP_EncryptUpdate(how, into + S3SEAL_HEAD, &moved, plain,
                        (int)length) != 1)
    return -1;

  if (EVP_EncryptFinal_ex(how, into + S3SEAL_HEAD + length, &moved) != 1)
    return -1;

  if (EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_GET_TAG, S3SEAL_TAG,
                          into + S3SEAL_HEAD + length) != 1)
    return -1;

  answer = 0;

  return answer;
}

int s3seal_openFrame(const unsigned char *key, const unsigned char *prefix,
                     const void *sealed, size_t length, unsigned char *into,
                     size_t *plainLength, unsigned int *part,
                     unsigned int *frame, int *last) {

  const unsigned char *from = sealed;
  EVP_CIPHER_CTX *how;
  unsigned char nonce[S3SEAL_NONCE];
  size_t body;
  int moved = 0;

  if (length < S3SEAL_OVERHEAD + 1 || length > S3SEAL_FRAME + S3SEAL_OVERHEAD)
    return -1;

  body = length - S3SEAL_OVERHEAD;

  *part = wordAt(from);
  *frame = wordAt(from + 4);
  *last = (from[8] & S3SEAL_LAST) != 0;

  how = EVP_CIPHER_CTX_new();

  if (how == NULL)
    return -1;

  defer EVP_CIPHER_CTX_free(how);

  nonceFor(prefix, *part, *frame, nonce);

  if (EVP_DecryptInit_ex(how, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_IVLEN, S3SEAL_NONCE, NULL) !=
          1 ||
      EVP_DecryptInit_ex(how, NULL, NULL, key, nonce) != 1)
    return -1;

  if (EVP_DecryptUpdate(how, NULL, &moved, from, S3SEAL_HEAD) != 1)
    return -1;

  if (EVP_DecryptUpdate(how, into, &moved, from + S3SEAL_HEAD, (int)body) != 1)
    return -1;

  if (EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_TAG, S3SEAL_TAG,
                          (void *)(from + S3SEAL_HEAD + body)) != 1)
    return -1;

  /**
   * The one call whose return value is the whole point. Everything above can
   * fail loudly; this one fails quietly and means the bytes are not the bytes
   * that were written.
   */
  if (EVP_DecryptFinal_ex(how, into + body, &moved) != 1)
    return -1;

  *plainLength = body;

  return 0;
}

/* ------------------------------------------------------ a whole body, once */

int s3seal_seal(const unsigned char *key, const unsigned char *prefix,
                unsigned int part, int last, const void *plain, size_t length,
                unsigned char *into, unsigned long long *sealedLength) {

  const unsigned char *from = plain;
  unsigned long long count = s3seal_frames(length);
  unsigned long long at = 0;

  for (unsigned long long n = 0; n < count; ++n) {

    size_t piece = length - (size_t)(n * S3SEAL_FRAME);

    if (piece > S3SEAL_FRAME)
      piece = S3SEAL_FRAME;

    if (s3seal_sealFrame(key, prefix, part, (unsigned int)n,
                         last && n + 1 == count, from + n * S3SEAL_FRAME,
                         piece, into + at) != 0)
      return -1;

    at += piece + S3SEAL_OVERHEAD;
  }

  if (sealedLength != NULL)
    *sealedLength = at;

  return 0;
}

int s3seal_open(const unsigned char *key, const unsigned char *prefix,
                const s3seal_layout_t *how, unsigned long long firstFrame,
                const void *sealed, size_t length, unsigned char *into,
                unsigned long long *plainLength) {

  const unsigned char *from = sealed;
  size_t at = 0;
  unsigned long long out = 0;
  unsigned long long where = firstFrame;

  if (!s3seal_layoutOk(how))
    return -1;

  while (at < length) {

    size_t left = length - at;
    size_t piece = left > S3SEAL_FRAME + S3SEAL_OVERHEAD
                       ? S3SEAL_FRAME + S3SEAL_OVERHEAD
                       : left;
    size_t got = 0;
    unsigned int part;
    unsigned int frame;
    unsigned int wantPart;
    unsigned int wantFrame;
    int last;

    if (s3seal_openFrame(key, prefix, from + at, piece, into + out, &got,
                         &part, &frame, &last) != 0)
      return -1;

    /**
     * The check the tag cannot make.
     *
     * A tag says a frame is intact. It says nothing about whether the frame
     * belongs *here* - a frame lifted from elsewhere in the same object, or a
     * whole part exchanged with another, carries its own honest header and
     * verifies perfectly. `how` is what turns "intact" into "in its place".
     */
    s3seal_placeOf(how, where, &wantPart, &wantFrame);

    if (part != wantPart || frame != wantFrame)
      return -1;

    /**
     * And a frame that says it closes a part has to be one that does.
     *
     * Not "closes the object": a part is sealed before anybody knows whether
     * it is the final one. Truncation is caught by the length arithmetic in
     * `headOf`, which is a better place for it - it happens once per request
     * rather than once per frame, and before anything is read.
     */
    if (last != s3seal_lastOf(how, where))
      return -1;

    ++where;
    at += piece;
    out += got;
  }

  if (plainLength != NULL)
    *plainLength = out;

  return 0;
}

/* ---------------------------------------------------------- the master key */

int s3seal_master_t.load(s3seal_master_t *self, const char *path) {

  struct stat about;
  int fd;

  self->loaded = 0;

  fd = open(path, O_RDONLY | O_CLOEXEC);

  if (fd < 0) {
    fprintf(stderr, "s3seal: no seed at %s: %s\n", path, strerror(errno));
    return -1;
  }

  defer close(fd);

  if (fstat(fd, &about) != 0)
    return -1;

  /* a key file others can read is one that has already been read */
  if ((about.st_mode & 0077) != 0) {
    fprintf(stderr, "s3seal: %s is readable by others - chmod 600 it\n", path);
    return -1;
  }

  if (about.st_size != S3SEAL_KEY) {
    fprintf(stderr, "s3seal: %s is %lld bytes, and a seed is %d\n", path,
            (long long)about.st_size, S3SEAL_KEY);
    return -1;
  }

  if (read(fd, self->seed, S3SEAL_KEY) != S3SEAL_KEY)
    return -1;

  self->loaded = 1;

  return 0;
}

int s3seal_master_t.make(s3seal_master_t *self, const char *path) {

  int fd;

  if (s3seal_random(self->seed, S3SEAL_KEY) != 0)
    return -1;

  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

  if (fd < 0) {
    fprintf(stderr, "s3seal: cannot make %s: %s\n", path, strerror(errno));
    return -1;
  }

  defer close(fd);

  if (write(fd, self->seed, S3SEAL_KEY) != S3SEAL_KEY || fsync(fd) != 0)
    return -1;

  self->loaded = 1;

  return 0;
}

/**
 * HKDF-SHA256 from the seed, with the object's name as info.
 *
 * So the key that wraps an object's data key is that object's alone, and a
 * blob copied out of one object's metadata into another's does not open.
 * Which matters more here than in a system with a catalogue: the metadata is
 * on the upstream, where anybody who can write the bucket can move it.
 */
static int wrappingKey(s3seal_master_t *self, const char *bound,
                       unsigned char *into) {

  EVP_PKEY_CTX *how = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  size_t room = S3SEAL_KEY;

  if (how == NULL)
    return -1;

  defer EVP_PKEY_CTX_free(how);

  if (EVP_PKEY_derive_init(how) != 1 ||
      EVP_PKEY_CTX_set_hkdf_md(how, EVP_sha256()) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(how, self->seed, S3SEAL_KEY) != 1 ||
      EVP_PKEY_CTX_add1_hkdf_info(how, (const unsigned char *)"s3seal/v1/",
                                  10) != 1 ||
      EVP_PKEY_CTX_add1_hkdf_info(how, (const unsigned char *)bound,
                                  (int)strlen(bound)) != 1)
    return -1;

  return EVP_PKEY_derive(how, into, &room) == 1 && room == S3SEAL_KEY ? 0 : -1;
}

int s3seal_master_t.wrap(s3seal_master_t *self, const unsigned char *dataKey,
                         const char *bound, unsigned char *blob) {

  EVP_CIPHER_CTX *how;
  unsigned char wrapping[S3SEAL_KEY];
  int moved = 0;

  if (!self->loaded)
    return -1;

  defer memset(wrapping, 0, S3SEAL_KEY);

  if (wrappingKey(self, bound, wrapping) != 0 ||
      s3seal_random(blob, S3SEAL_NONCE) != 0)
    return -1;

  how = EVP_CIPHER_CTX_new();

  if (how == NULL)
    return -1;

  defer EVP_CIPHER_CTX_free(how);

  if (EVP_EncryptInit_ex(how, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_IVLEN, S3SEAL_NONCE, NULL) !=
          1 ||
      EVP_EncryptInit_ex(how, NULL, NULL, wrapping, blob) != 1 ||
      EVP_EncryptUpdate(how, blob + S3SEAL_NONCE, &moved, dataKey,
                        S3SEAL_KEY) != 1 ||
      EVP_EncryptFinal_ex(how, blob + S3SEAL_NONCE + S3SEAL_KEY, &moved) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_GET_TAG, S3SEAL_TAG,
                          blob + S3SEAL_NONCE + S3SEAL_KEY) != 1)
    return -1;

  return 0;
}

int s3seal_master_t.unwrap(s3seal_master_t *self, const unsigned char *blob,
                           const char *bound, unsigned char *dataKey) {

  EVP_CIPHER_CTX *how;
  unsigned char wrapping[S3SEAL_KEY];
  int moved = 0;

  if (!self->loaded)
    return -1;

  defer memset(wrapping, 0, S3SEAL_KEY);

  if (wrappingKey(self, bound, wrapping) != 0)
    return -1;

  how = EVP_CIPHER_CTX_new();

  if (how == NULL)
    return -1;

  defer EVP_CIPHER_CTX_free(how);

  if (EVP_DecryptInit_ex(how, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_IVLEN, S3SEAL_NONCE, NULL) !=
          1 ||
      EVP_DecryptInit_ex(how, NULL, NULL, wrapping, blob) != 1 ||
      EVP_DecryptUpdate(how, dataKey, &moved, blob + S3SEAL_NONCE,
                        S3SEAL_KEY) != 1 ||
      EVP_CIPHER_CTX_ctrl(how, EVP_CTRL_GCM_SET_TAG, S3SEAL_TAG,
                          (void *)(blob + S3SEAL_NONCE + S3SEAL_KEY)) != 1)
    return -1;

  return EVP_DecryptFinal_ex(how, dataKey + S3SEAL_KEY, &moved) == 1 ? 0 : -1;
}
/* ------------------------------------------------- the digests S3 asks for */

void s3seal_sha256(const void *bytes, size_t length, unsigned char *into) {

  unsigned int wrote = 0;

  EVP_Digest(bytes, length, into, &wrote, EVP_sha256(), NULL);
}

void s3seal_sha256Hex(const void *bytes, size_t length, char *into) {

  unsigned char digest[32];

  s3seal_sha256(bytes, length, digest);
  s3seal_toHex(digest, sizeof digest, into);
}

void s3seal_hmacSha256(const void *key, size_t keyLength, const void *bytes,
                      size_t length, unsigned char *into) {

  unsigned int wrote = 0;

  HMAC(EVP_sha256(), key, (int)keyLength, bytes, length, into, &wrote);
}

void s3seal_md5(const void *bytes, size_t length, unsigned char *into) {

  unsigned int wrote = 0;

  EVP_Digest(bytes, length, into, &wrote, EVP_md5(), NULL);
}

void s3seal_md5Hex(const void *bytes, size_t length, char *into) {

  unsigned char digest[16];

  s3seal_md5(bytes, length, digest);
  s3seal_toHex(digest, sizeof digest, into);
}

/* ------------------------------------------------------------ CRC-64/NVME */

/**
 * The reflected NVMe polynomial, which is what S3 checks against.
 *
 * Built once on first use rather than written out as 256 constants: the table
 * is 2 KB either way and a generated one is 2 KB nobody can check by reading.
 */
/**
 * Eight tables, not one, and eight bytes a turn.
 *
 * The obvious loop takes one byte per turn and every turn depends on the one
 * before it - a chain the processor cannot get ahead of. Measured at 701 MB/s
 * against AES-256-GCM's 8047 on the same machine, which is the wrong way
 * round for a checksum next to a cipher, and on a ten gigabyte upload it was
 * fourteen seconds against the cipher's one and a half.
 *
 * The slice-by-eight arrangement is the standard answer: eight tables, each
 * holding the effect of a byte at one of eight positions, so eight bytes are
 * folded in with eight independent lookups and one exclusive-or. The chain is
 * eight times shorter and the lookups pipeline.
 *
 * It is still portable C - no intrinsics, nothing to detect at run time. A
 * `PCLMULQDQ` version would be faster again and would need both.
 */
static unsigned long long s3seal_crcTable[8][256];
static int s3seal_crcReady;

static void s3seal_crcBuild(void) {

  /* 0xAD93D23594C93659 reflected */
  const unsigned long long poly = 0x9A6C9329AC4BC9B5ull;

  for (unsigned int at = 0; at < 256; ++at) {

    unsigned long long one = at;

    for (int bit = 0; bit < 8; ++bit)
      one = (one & 1) != 0 ? (one >> 1) ^ poly : one >> 1;

    s3seal_crcTable[0][at] = one;
  }

  /* each further table is the one before it pushed on by another byte */
  for (unsigned int at = 0; at < 256; ++at) {

    unsigned long long one = s3seal_crcTable[0][at];

    for (int slice = 1; slice < 8; ++slice) {
      one = s3seal_crcTable[0][one & 0xff] ^ (one >> 8);
      s3seal_crcTable[slice][at] = one;
    }
  }

  s3seal_crcReady = 1;
}

unsigned long long s3seal_crc64(const void *bytes, size_t length,
                                unsigned long long from) {

  const unsigned char *at = bytes;
  unsigned long long value = ~from;

  if (!s3seal_crcReady)
    s3seal_crcBuild();

  /* the unaligned head, one byte at a time */
  while (length > 0 && ((uintptr_t)at & 7) != 0) {
    value = s3seal_crcTable[0][(value ^ *at++) & 0xff] ^ (value >> 8);
    --length;
  }

  while (length >= 8) {

    unsigned long long eight;

    memcpy(&eight, at, 8);

    /* the running value is folded into the first eight bytes, then all eight
       are looked up at once - the table index for each position is a byte of
       the exclusive-or, and the results simply combine */
    eight ^= value;

    value = s3seal_crcTable[7][eight & 0xff] ^
            s3seal_crcTable[6][(eight >> 8) & 0xff] ^
            s3seal_crcTable[5][(eight >> 16) & 0xff] ^
            s3seal_crcTable[4][(eight >> 24) & 0xff] ^
            s3seal_crcTable[3][(eight >> 32) & 0xff] ^
            s3seal_crcTable[2][(eight >> 40) & 0xff] ^
            s3seal_crcTable[1][(eight >> 48) & 0xff] ^
            s3seal_crcTable[0][(eight >> 56) & 0xff];

    at += 8;
    length -= 8;
  }

  while (length-- > 0)
    value = s3seal_crcTable[0][(value ^ *at++) & 0xff] ^ (value >> 8);

  return ~value;
}

void s3seal_crc64Text(unsigned long long value, char *into) {

  static const char *alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned char raw[8];
  int at = 0;

  for (int one = 0; one < 8; ++one)
    raw[one] = (unsigned char)(value >> (56 - one * 8));

  /* eight bytes is two full groups of three plus two, so one pad character */
  for (int one = 0; one < 6; one += 3) {

    unsigned int three = ((unsigned int)raw[one] << 16) |
                         ((unsigned int)raw[one + 1] << 8) | raw[one + 2];

    into[at++] = alphabet[(three >> 18) & 0x3f];
    into[at++] = alphabet[(three >> 12) & 0x3f];
    into[at++] = alphabet[(three >> 6) & 0x3f];
    into[at++] = alphabet[three & 0x3f];
  }

  {
    unsigned int two = ((unsigned int)raw[6] << 16) | ((unsigned int)raw[7] << 8);

    into[at++] = alphabet[(two >> 18) & 0x3f];
    into[at++] = alphabet[(two >> 12) & 0x3f];
    into[at++] = alphabet[(two >> 6) & 0x3f];
    into[at++] = '=';
  }

  into[at] = 0;
}
