# s3seal

An S3 proxy that encrypts, and still tells the truth about it.

## The gap it is aimed at

Three open projects encrypt in front of S3, and each gives something up at
the same place:

| | frames | range GET | multipart | multipart encrypted | plaintext ETag |
|---|---|---|---|---|---|
| Intrinsec/s3proxy | no | no | **refused** | — | — |
| s3-encryption-gateway | yes | yes | yes | **no** | — |
| rclone crypt + serve s3 | yes | yes | yes | yes | **no** |
| s3seal | yes | yes | yes | yes | yes |

You can have two of {transparent proxy, real encryption, correct ETag}. The
third costs somewhere to keep metadata, and a proxy is not supposed to have
one.

**s3seal keeps its metadata on the upstream S3 itself.** No database, no
sidecar objects, no second system to keep consistent.

## How

**Framed bodies.** 64 KiB frames, each sealed with AES-256-GCM under its own
nonce and tag. A range is a range; a part is a whole number of frames.

**Sizes need no metadata.** A frame is a fixed stride on the wire, so
plaintext length is arithmetic from ciphertext length and back. That is what
lets `ListObjectsV2` answer honestly without reading a single object.

**Self-locating frames.** Every frame carries `[part:4][frame:4][flags:1]` in
front, as authenticated associated data. A proxy cannot know a frame's global
index when it seals it — `UploadPart` arrives out of order and nobody knows
how long the earlier parts are — so the number travels with the frame.

**Places are checked, not just tags.** A tag says a frame is intact. It does
not say the frame belongs *here*: a whole part exchanged with another carries
honest headers and verifies perfectly. So opening takes the object's layout —
one number, the part size, out of the metadata that had to be read for the key
anyway — and refuses any frame that is not where it should be.

**Multipart is assembled, not passed through.** Parts are sealed into objects
of their own under a reserved prefix. `CompleteMultipartUpload` then creates
the real object with `UploadPartCopy` — server side, no bytes back through the
proxy — at the one moment when every part's plaintext MD5 is known, so the
object is created *with the right ETag in its metadata from the start*.

That also makes each part's own ETag correct, which nothing else in the field
manages either.

## State

**It runs.** `tests/proxy.sh` starts a MinIO in a container, puts the proxy in
front of it and goes at it with `aws` and `curl` — 29 checks, and the ones
worth naming:

    ok       and its ETag is the plaintext MD5
    ok       and its length is the plaintext length
    ok       the upstream holds more bytes than the client sent
    ok       and they are not the client's bytes
    ok       the upstream holds only a wrapped key
    ok       and one that crosses a frame boundary
    ok       a listing reports the plaintext size
    ok       and the upstream reports the sealed one
    ok       a 20 MB object goes up as a multipart upload
    ok       and its ETag has the part count on it
    ok       a range across a part boundary is right
    ok       and the parked parts were cleaned up

`tests/run.sh` is the format on its own, 30 checks, no network needed.

Done:

- the frame format — sizes, ranges, wrapping, and every tamper refused
- SigV4 both ways: clients verified against our credentials, upstream signed
  with its own
- PUT, GET, HEAD, DELETE, ranged GET, listings with the sizes put right
- the body streams out through a pipe, so an object is never whole in memory

- **multipart**, assembled rather than passed through: parts are sealed into
  objects of their own under a reserved prefix, and the completion builds the
  real object out of them with `UploadPartCopy` — server side, no bytes back
  through the proxy — at the one moment every part's plaintext MD5 is known.
  So the object carries the right ETag *and* the right per-part ETags.
- connections are reused through one shared cache

Not written yet:

- server-side copy, versioning, tagging, and the rest of the surface
- **a client's part size has to be a whole number of 64 KiB frames.** Every
  round default — 5, 8, 16 MiB — is one, and the completion says so plainly
  when it is not. It is what lets one number describe the layout.

## Running it

    ./build.sh

    S3SEAL_UPSTREAM=https://s3.eu-central-1.amazonaws.com \
    S3SEAL_UPSTREAM_ACCESS=... S3SEAL_UPSTREAM_SECRET=... \
    ./run.sh

On a first run it makes a seed and a credentials file and prints the access
key it invented. **Keep the seed.** Without it every object on the upstream is
noise — which is the point, and also the risk.

    tests/run.sh          the format, no network needed
    tests/proxy.sh        end to end, needs docker and the aws cli
    tests/bench.sh [MB]   what the sealing costs

## What it costs

Against a MinIO in a container on loopback, so the absolute figures say more
about this machine than about anybody's production. The ratios are the point.

|                       | 64 MB | 256 MB |
|-----------------------|-------|--------|
| write, upstream       | 460 MB/s | 541 MB/s |
| write, through s3seal | 249 MB/s | 260 MB/s |
| read, upstream        | 854 MB/s | 1056 MB/s |
| read, through s3seal  | 542 MB/s | 348 MB/s |
| **4 kB range**        | **3.1 ms** | **3.0 ms** |

The last row is the design in one number. A 4 kB range costs the same out of
a 256 MB object as out of a 64 MB one, because it fetches one frame and opens
one frame. The whole-object read behind it went from 0.08 s to 0.25 s over the
same step — so against a design that seals the body as a single AEAD blob and
must fetch all of it to reach the middle, the gap is 25x at 64 MB and **85x at
256 MB**, and it keeps growing.

Framing costs **0.038%** on the wire: 25 bytes per 64 KiB frame.

Written in metalang, on `meta_fetch.h` — which was written for this and is
documented in `doc/fetch.md` of the metalanguage tree.
