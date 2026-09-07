#!/usr/bin/env python3
"""
What the sealing costs, against a proxy and an upstream that are both running.

Every number here is measured on this machine against a MinIO in a container,
so the absolute figures say more about loopback and a laptop than about
anybody's production. What they are for is the *ratios*: proxy against
upstream, and a small range against a large object.

    tests/bench.py <proxy-url> <upstream-url> [MB]
"""
import hashlib
import os
import statistics
import sys
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

PROXY = sys.argv[1]
UPSTREAM = sys.argv[2]
SIZE = int(sys.argv[3] if len(sys.argv) > 3 else 64) * 1024 * 1024

FRAME = 65536
OVERHEAD = 25

mine = Credentials(os.environ["PROXY_KEY"], os.environ["PROXY_SECRET"])
theirs = Credentials(os.environ["UPSTREAM_KEY"], os.environ["UPSTREAM_SECRET"])
region = "us-east-1"


def ask(who, method, url, body=b"", headers=None):
    request = AWSRequest(method=method, url=url, data=body)
    request.headers["x-amz-content-sha256"] = hashlib.sha256(body).hexdigest()
    for name, value in (headers or {}).items():
        request.headers[name] = value
    SigV4Auth(who, "s3", region).add_auth(request)
    sending = urllib.request.Request(url, data=body or None, method=method,
                                     headers=dict(request.headers))
    try:
        with urllib.request.urlopen(sending, timeout=600) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as bad:
        return bad.code, bad.read()


def timed(what, *args, **kwargs):
    started = time.perf_counter()
    got = what(*args, **kwargs)
    return time.perf_counter() - started, got


def say(label, value):
    print("  %-46s %s" % (label, value))


def rate(seconds, bytes_):
    return "%.2f s  %.0f MB/s" % (seconds, bytes_ / seconds / 1e6)


body = os.urandom(SIZE)
digest = hashlib.md5(body).hexdigest()

ask(mine, "PUT", PROXY + "/bench")
ask(theirs, "PUT", UPSTREAM + "/bare")

print("\n--- one %d MB object ---" % (SIZE // (1024 * 1024)))

# ------------------------------------------------------------------ writing

bare, _ = timed(ask, theirs, "PUT", UPSTREAM + "/bare/x.bin", body)
say("straight to the upstream", rate(bare, SIZE))

sealed, _ = timed(ask, mine, "PUT", PROXY + "/bench/x.bin", body)
say("through s3seal", rate(sealed, SIZE))
say("the sealing tax", "%.2fx" % (sealed / bare))

# ------------------------------------------------------------------ reading

bareGet, (_, raw) = timed(ask, theirs, "GET", UPSTREAM + "/bare/x.bin")
say("reading it back from the upstream", rate(bareGet, SIZE))

sealedGet, (_, back) = timed(ask, mine, "GET", PROXY + "/bench/x.bin")
say("reading it back through s3seal", rate(sealedGet, SIZE))
say("the opening tax", "%.2fx" % (sealedGet / bareGet))

say("and it is the same bytes",
    "yes" if hashlib.md5(back).hexdigest() == digest else "NO")

# ---------------------------------------------------------------- the frames

status, _ = ask(mine, "HEAD", PROXY + "/bench/x.bin")
_, stored = ask(theirs, "HEAD", UPSTREAM + "/bench/x.bin")

frames = (SIZE + FRAME - 1) // FRAME
onWire = SIZE + frames * OVERHEAD

print("\n--- what the framing costs on the wire ---")
say("frames", "%d of %d bytes" % (frames, FRAME))
say("stored", "%d bytes for %d" % (onWire, SIZE))
say("overhead", "%.4f%%" % ((onWire - SIZE) / SIZE * 100))

# ----------------------------------------------------------------- ranges

print("\n--- a 4 kB range out of the middle ---")

at = SIZE // 2
want = 4096
head = {"range": "bytes=%d-%d" % (at, at + want - 1)}

runs = []
for _ in range(5):
    seconds, (code, piece) = timed(ask, mine, "GET", PROXY + "/bench/x.bin",
                                   b"", head)
    runs.append(seconds)

right = piece == body[at:at + want]

bareRuns = []
for _ in range(5):
    seconds, _ = timed(ask, theirs, "GET", UPSTREAM + "/bare/x.bin", b"", head)
    bareRuns.append(seconds)

say("through s3seal", "%.1f ms" % (statistics.median(runs) * 1000))
say("straight to the upstream", "%.1f ms" % (statistics.median(bareRuns) * 1000))
say("and it is the right 4096 bytes", "yes" if right else "NO")

# What a design that seals the whole body as one AEAD blob would have to do,
# because it cannot open the middle without the front. Not measured on such a
# design - it is the same upstream GET of the whole object, timed above.
print("\n--- the same range without framing (derived, not measured) ---")
say("whole-object fetch it would need", rate(bareGet, SIZE))
say("against the framed read", "%.1f ms" % (statistics.median(runs) * 1000))
say("ratio", "%.0fx" % (bareGet / statistics.median(runs)))

print("")
