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
    tests/pump.py         a PUT, timed only while bytes move
    tests/drain.py        a GET, timed only after the first byte

## What it costs

Against a MinIO in a container on loopback, so the absolute figures say more
about this machine than about anybody's production. The ratios are the point.

**Writing.** A 10 GB PUT with `S3SEAL_ETAG=opaque`, clocked only while bytes
are moving, with the upstream's final commit left out (`tests/pump.py`):

| PUT, `opaque`  | upstream direct | through s3seal |
|----------------|-----------------|----------------|
| 64 MB   | 880 MB/s | 814 MB/s |
| 256 MB  | 949 MB/s | 659 MB/s |
| 1 GB    | 963 MB/s | 639 MB/s |
| 10 GB   | 884 MB/s | **605 MB/s** |

The mode matters and so does the size. A 64 MB PUT reaches 93% of the wire
because the pipes and socket buffers in the path swallow most of it before the
sealer becomes the ceiling; from a quarter gigabyte on, the buffers no longer
help and it settles at about two thirds. That steady state is the honest
figure, for a body that is framed, encrypted with AES-256-GCM and checksummed
with CRC-64/NVME on the way through. The sealing stage is what limits it: busy
the whole time, but only ~42% of that computing, so the next step is to seal
several frames at once rather than one at a time.

**`S3SEAL_ETAG=md5` cannot be measured this way at all.** It holds a whole
part to hash it, so it takes the body off the socket at 2.1 GB/s and does the
work *after* the last byte — `tests/pump.py` would report 2134 MB/s and a
3.26 s tail on a gigabyte. End to end that mode moves 240 MB/s at 64 MB and
285 MB/s at 1 GB, against 516 and 790 MB/s for the upstream measured the same
way. Buying a plaintext-MD5 ETag costs roughly half the throughput.

**Reading.** The same treatment for GETs — the wait for the first byte
reported apart from the rate over the rest (`tests/drain.py`):

| object | upstream direct | through s3seal |
|--------|-----------------|----------------|
| 64 MB   | 1919 MB/s | 1193 MB/s |
| 128 MB  | 1598 MB/s | 1096 MB/s |
| 256 MB  | 1311 MB/s | 1115 MB/s |
| 512 MB  | 1308 MB/s | 1073 MB/s |
| 1 GB    | 1420 MB/s | 1179 MB/s |

Opening is flat in the size of the object — ~1.1 GB/s across a sixteen-fold
range — because the read path never holds the object: a reader task pulls from
the upstream, opens frame by frame and writes into a pipe the response streams
from. First bytes leave after 2–4 ms regardless of size.

**Short objects, and what a total hides.** `tests/bench.sh` times whole
requests from a Python client that keeps the body, the sealed copy and the
plain copy in memory at once and hashes them - including a SHA-256 of the body
inside its own clock, which is 0.063 s at 256 MB. That client's cost per byte
grows with the object, which is why its read column falls away with size while
the table above stays flat. What it is still good for is the range:

|                | 64 MB | 256 MB |
|----------------|-------|--------|
| **4 kB range** | **3.0 ms** | **3.8 ms** |

`S3SEAL_ETAG=md5` buys a plaintext-MD5 ETag by holding a whole part to hash
it; `opaque` streams straight through and returns an ETag that is a digest but
not an MD5 — which S3 itself permits, and which is what every server-side
encrypted object on AWS already returns.

The last row is the design in one number. A 4 kB range costs about the same
out of a 256 MB object as out of a 64 MB one, because it fetches one frame and
opens one frame; nearly all of those milliseconds are connection setup. The
whole-object read behind it grows with the object — so against a design that
seals the body as a single AEAD blob and must fetch all of it to reach the
middle, the gap is **20x at 64 MB and 92x at 256 MB**, and it keeps growing.

Framing costs **0.038%** on the wire: 25 bytes per 64 KiB frame.

Written in metalang, on `meta_fetch.h` — which was written for this and is
documented in `doc/fetch.md` of the metalanguage tree.
