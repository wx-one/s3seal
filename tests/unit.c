/**
 * The format, checked without a network, a proxy or an upstream in sight.
 *
 * Everything here is a claim frame.h makes in prose, turned into something
 * that fails when it stops being true. The size arithmetic gets the most
 * attention because it is the claim that lets this project answer a listing
 * honestly, and an off-by-one in it would be invisible until a client
 * compared a length.
 */
#include "frame.h"
#include "s3seal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int failures;
static int ran;

static void check(const char *what, int ok) {

  ++ran;

  if (ok) {
    printf("%-58s ok\n", what);
    return;
  }

  printf("%-58s FAIL\n", what);
  ++failures;
}

/* ------------------------------------------------------------ the sizes */

static void trySizes(void) {

  printf("\n--- the size arithmetic ---\n");

  check("nothing seals to nothing", s3seal_sealedSize(0) == 0);
  check("and back", s3seal_plainSize(0, NULL) == 0);

  check("one byte costs one header and one tag",
        s3seal_sealedSize(1) == 1 + S3SEAL_OVERHEAD);

  check("a full frame costs one of each",
        s3seal_sealedSize(S3SEAL_FRAME) == S3SEAL_FRAME + S3SEAL_OVERHEAD);

  check("a frame and a byte costs two",
        s3seal_sealedSize(S3SEAL_FRAME + 1) ==
            S3SEAL_FRAME + 1 + 2 * S3SEAL_OVERHEAD);

  /**
   * The one that matters. Every length from nothing to a few frames, there
   * and back, because this is what a HEAD and a listing answer with and a
   * single wrong length is a client that thinks an object is truncated.
   */
  {
    int good = 1;

    for (unsigned long long plain = 0; plain <= 3 * S3SEAL_FRAME + 7;
         plain += (plain < 2000 ? 1 : 977)) {

      int ok = 0;
      unsigned long long sealed = s3seal_sealedSize(plain);

      if (s3seal_plainSize(sealed, &ok) != plain || !ok) {
        printf("  %llu -> %llu -> %llu\n", plain, sealed,
               s3seal_plainSize(sealed, &ok));
        good = 0;
        break;
      }
    }

    check("every length survives the round trip", good);
  }

  /* something that was in the bucket before the proxy was */
  {
    int ok = 1;

    s3seal_plainSize(S3SEAL_OVERHEAD, &ok);

    check("a length that is not ours is refused, not guessed", !ok);
  }
}

/* ------------------------------------------------------------ one body */

static void tryFrames(void) {

  unsigned char key[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
  size_t plainLength = 3 * S3SEAL_FRAME + 1234;
  unsigned char *plain = malloc(plainLength);
  unsigned char *sealed = malloc((size_t)s3seal_sealedSize(plainLength));
  unsigned char *back = malloc(plainLength);
  unsigned long long wrote = 0;
  unsigned long long read = 0;
  s3seal_layout_t how = {0, 0};

  printf("\n--- sealing and opening ---\n");

  how.plain = plainLength;

  s3seal_random(key, sizeof key);
  s3seal_random(prefix, sizeof prefix);
  s3seal_random(plain, plainLength);

  check("a body seals",
        s3seal_seal(key, prefix, 0, 1, plain, plainLength, sealed, &wrote) ==
            0);

  check("to exactly the size it was promised",
        wrote == s3seal_sealedSize(plainLength));

  check("and opens", s3seal_open(key, prefix, &how, 0, sealed, (size_t)wrote,
                                 back, &read) == 0);

  check("to the same length", read == plainLength);
  check("and the same bytes", memcmp(plain, back, plainLength) == 0);

  /* --------------------------------------------------- and does not open */

  {
    unsigned char other[S3SEAL_KEY];

    s3seal_random(other, sizeof other);

    check("not under another key",
          s3seal_open(other, prefix, &how, 0, sealed, (size_t)wrote, back,
                      &read) != 0);
  }

  {
    unsigned char kept = sealed[S3SEAL_HEAD + 40];

    sealed[S3SEAL_HEAD + 40] ^= 0x01;

    check("not with a bit turned over in the ciphertext",
          s3seal_open(key, prefix, &how, 0, sealed, (size_t)wrote, back,
                      &read) != 0);

    sealed[S3SEAL_HEAD + 40] = kept;
  }

  {
    unsigned char kept = sealed[7];

    /* the frame number in the header - plaintext, but associated data */
    sealed[7] ^= 0x01;

    check("nor with the header rewritten, which is the point of it",
          s3seal_open(key, prefix, &how, 0, sealed, (size_t)wrote, back,
                      &read) != 0);

    sealed[7] = kept;
  }

  /**
   * The attack a tag alone does not stop: two frames of the same object,
   * both honest, in the wrong order. Every tag checks out and the body is
   * wrong, which is why `s3seal_open` compares the frame number against
   * where it is rather than trusting what it reads.
   */
  {
    size_t stride = S3SEAL_FRAME + S3SEAL_OVERHEAD;
    unsigned char *swap = malloc(stride);

    memcpy(swap, sealed, stride);
    memcpy(sealed, sealed + stride, stride);
    memcpy(sealed + stride, swap, stride);

    check("nor with two good frames swapped round",
          s3seal_open(key, prefix, &how, 0, sealed, (size_t)wrote, back,
                      &read) != 0);

    memcpy(swap, sealed, stride);
    memcpy(sealed, sealed + stride, stride);
    memcpy(sealed + stride, swap, stride);

    free(swap);
  }

  check("and opens again once it is put back",
        s3seal_open(key, prefix, &how, 0, sealed, (size_t)wrote, back, &read) ==
            0);

  /* a frame that claims to close a part where none ends is refused; the
     truncation of a whole object is caught by the length arithmetic instead */
  {
    unsigned long long shorter = wrote - (S3SEAL_FRAME + S3SEAL_OVERHEAD);

    check("and a truncated object is refused",
          s3seal_open(key, prefix, &how, 0, sealed, (size_t)shorter, back,
                      &read) != 0);
  }

  free(plain);
  free(sealed);
  free(back);
}

/* --------------------------------------------------------------- ranges */

static void tryRanges(void) {

  unsigned char key[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
  size_t plainLength = 5 * S3SEAL_FRAME + 999;
  unsigned char *plain = malloc(plainLength);
  unsigned char *sealed = malloc((size_t)s3seal_sealedSize(plainLength));
  unsigned char *back = malloc(plainLength + S3SEAL_FRAME);
  unsigned long long wrote = 0;
  s3seal_layout_t how = {0, 0};
  int good = 1;

  printf("\n--- ranges ---\n");

  how.plain = plainLength;

  s3seal_random(key, sizeof key);
  s3seal_random(prefix, sizeof prefix);
  s3seal_random(plain, plainLength);

  s3seal_seal(key, prefix, 0, 1, plain, plainLength, sealed, &wrote);

  /**
   * A range is answered by fetching whole frames and trimming. The check is
   * that the trimmed answer is the same bytes the plaintext has there - for
   * ranges that start and end inside frames, on frame boundaries, at the
   * very end, and past it.
   */
  {
    unsigned long long tries[][2] = {
      {0, 1},
      {0, plainLength},
      {1, 100},
      {S3SEAL_FRAME - 1, 2},
      {S3SEAL_FRAME, S3SEAL_FRAME},
      {2 * S3SEAL_FRAME + 5, 3 * S3SEAL_FRAME},
      {plainLength - 1, 1},
      {plainLength - 500, 10000},
      {5 * S3SEAL_FRAME, 999},
    };

    for (size_t at = 0; at < sizeof tries / sizeof *tries; ++at) {

      unsigned long long from, length, skip, first, out = 0;
      unsigned long long want = tries[at][1];

      s3seal_span(tries[at][0], want, plainLength, &from, &length, &skip,
                  &first);

      if (s3seal_open(key, prefix, &how, first, sealed + from, (size_t)length,
                      back, &out) != 0) {
        printf("  range %llu+%llu would not open\n", tries[at][0], want);
        good = 0;
        break;
      }

      if (want > plainLength - tries[at][0])
        want = plainLength - tries[at][0];

      if (out < skip + want ||
          memcmp(back + skip, plain + tries[at][0], (size_t)want) != 0) {
        printf("  range %llu+%llu came back wrong\n", tries[at][0], want);
        good = 0;
        break;
      }
    }
  }

  check("every range is the bytes that are there", good);

  free(plain);
  free(sealed);
  free(back);
}

/* ----------------------------------------------------------- multipart */

/**
 * The claim the whole project rests on: parts sealed separately, with no
 * knowledge of each other, concatenated by somebody else, and the result
 * opens as one object.
 *
 * That is what `CompleteMultipartUpload` does server-side, and the reason
 * the frame header carries its own `(part, frame)` rather than deriving it
 * from a position nobody knows yet.
 */
static void tryMultipart(void) {

  unsigned char key[S3SEAL_KEY];
  unsigned char prefix[S3SEAL_NONCE_PREFIX];
  size_t partLength = 2 * S3SEAL_FRAME;
  size_t lastLength = S3SEAL_FRAME / 2;
  size_t plainLength = 3 * partLength + lastLength;
  unsigned char *plain = malloc(plainLength);
  unsigned char *joined = malloc((size_t)s3seal_sealedSize(plainLength) + 64);
  unsigned char *back = malloc(plainLength);
  unsigned long long at = 0;
  unsigned long long read = 0;
  unsigned long long perPart = partLength / S3SEAL_FRAME;
  s3seal_layout_t how = {0, 0};
  int sealedOk = 1;

  printf("\n--- multipart, sealed apart and joined by somebody else ---\n");

  how.partSize = partLength;
  how.plain = plainLength;

  s3seal_random(key, sizeof key);
  s3seal_random(prefix, sizeof prefix);
  s3seal_random(plain, plainLength);

  /* four parts, each sealed as if by a different worker on a different
     machine, knowing only its own part number */
  for (unsigned int part = 1; part <= 4; ++part) {

    size_t length = part == 4 ? lastLength : partLength;
    unsigned long long wrote = 0;

    /* every part closes itself, which is what the writer knows at the time */
    if (s3seal_seal(key, prefix, part, 1, plain + (part - 1) * partLength,
                    length, joined + at, &wrote) != 0)
      sealedOk = 0;

    at += wrote;
  }

  check("four parts seal on their own", sealedOk);

  check("and the join is the size the arithmetic says",
        at == s3seal_sealedSize(plainLength));

  /**
   * Opened with `s3seal_open`'s frame check turned on for the first part
   * only - across a part boundary the frame number starts again at zero,
   * which is exactly why the header carries the part as well.
   */
  {
    unsigned long long out = 0;
    unsigned long long where = 0;
    int good = 1;

    for (unsigned int part = 1; part <= 4 && good; ++part) {

      size_t length = part == 4 ? lastLength : partLength;
      unsigned long long piece = s3seal_sealedSize(length);

      if (s3seal_open(key, prefix, &how, (part - 1) * perPart, joined + where,
                      (size_t)piece, back + out, &read) != 0)
        good = 0;

      where += piece;
      out += read;
    }

    check("the joined object opens", good);
    check("to the same length", out == plainLength);
    check("and the same bytes", memcmp(plain, back, plainLength) == 0);
  }

  /**
   * And the header is what stops the parts being shuffled. Part 2 put where
   * part 1 was keeps saying it is part 2, so its nonce and its associated
   * data are part 2's, and nothing about it opens where part 1 belongs.
   */
  {
    unsigned long long piece = s3seal_sealedSize(partLength);
    unsigned char *swap = malloc((size_t)piece);
    unsigned long long out = 0;

    memcpy(swap, joined, (size_t)piece);
    memcpy(joined, joined + piece, (size_t)piece);
    memcpy(joined + piece, swap, (size_t)piece);

    /**
     * Every frame in the moved part is intact and every tag verifies. What
     * gives it away is that its header still says which part it is, and the
     * layout says which part belongs at this offset. This is the check the
     * first version of the format did not make.
     */
    check("and a whole part moved to another part's place is refused",
          s3seal_open(key, prefix, &how, 0, joined, (size_t)piece, back,
                      &out) != 0);

    free(swap);
  }

  free(plain);
  free(joined);
  free(back);
}

/* ------------------------------------------------------------ the keys */

static void tryKeys(const char *dir) {

  s3seal_master_t master = {0};
  char path[512];
  unsigned char dataKey[S3SEAL_KEY];
  unsigned char came[S3SEAL_KEY];
  unsigned char blob[S3SEAL_BLOB];

  printf("\n--- wrapping ---\n");

  snprintf(path, sizeof path, "%s/seed", dir);
  unlink(path);

  check("a seed is made", master.make(path) == 0);

  s3seal_random(dataKey, sizeof dataKey);

  check("a data key wraps", master.wrap(dataKey, "bucket/some/key", blob) == 0);

  check("and comes back",
        master.unwrap(blob, "bucket/some/key", came) == 0 &&
            memcmp(dataKey, came, S3SEAL_KEY) == 0);

  /**
   * The metadata lives on the upstream, where anybody who can write the
   * bucket can move it. Binding the wrap to the object's name is what makes
   * moving it useless.
   */
  check("but not under another object's name",
        master.unwrap(blob, "bucket/other/key", came) != 0);

  {
    s3seal_master_t again = {0};

    check("and the seed reads back",
          again.load(path) == 0 &&
              again.unwrap(blob, "bucket/some/key", came) == 0);
  }
}

int main(int count, char **argument) {

  const char *dir = count > 1 ? argument[1] : ".";

  trySizes();
  tryFrames();
  tryRanges();
  tryMultipart();
  tryKeys(dir);

  printf("\n%d run, %d failed\n", ran, failures);

  return failures == 0 ? 0 : 1;
}
