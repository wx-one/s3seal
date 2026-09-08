#!/usr/bin/env python3
"""
A workload with more than one client in it.

Every other benchmark here moves one object at a time, which answers what a
single stream costs and nothing about what a proxy is for. This one runs a
mix - small objects and large, reads and writes and ranges - from many
connections at once, against s3seal and against the upstream in turn, so the
two columns are the same work.

    tests/mixed.py <url> <access> <secret> <bucket> [seconds] [clients...]

The client is Python and can itself run out of breath, so the upstream column
is also the honest ceiling of the measuring tool: where the two columns meet,
believe neither.
"""
import hashlib
import hmac
import os
import random
import statistics
import sys
import threading
import time
from http.client import HTTPConnection
from urllib.parse import urlparse

URL = sys.argv[1]
ACCESS = sys.argv[2]
SECRET = sys.argv[3]
BUCKET = sys.argv[4]
SECONDS = float(sys.argv[5]) if len(sys.argv) > 5 else 15.0
LEVELS = [int(x) for x in sys.argv[6:]] or [1, 8, 32]

parsed = urlparse(URL)
HOST = parsed.hostname
PORT = parsed.port or 80
REGION = "us-east-1"

# what the objects look like: (name, bytes, share of the object population)
SIZES = [("small", 64 * 1024, 70), ("medium", 1024 * 1024, 20),
         ("large", 16 * 1024 * 1024, 10)]

# what the clients do: (operation, share)
MIX = [("get", 60), ("range", 15), ("put", 20), ("list", 5)]

BODIES = {name: os.urandom(size) for name, size, _ in SIZES}
POPULATION = 60


def pick(weighted, rng):
    total = sum(w for _, w in weighted)
    at = rng.uniform(0, total)
    for value, weight in weighted:
        at -= weight
        if at <= 0:
            return value
    return weighted[-1][0]


def sign(method, path, headers, payload):
    now = time.gmtime()
    amzDate = time.strftime("%Y%m%dT%H%M%SZ", now)
    day = time.strftime("%Y%m%d", now)

    headers["x-amz-date"] = amzDate
    headers["x-amz-content-sha256"] = payload
    headers["host"] = "%s:%d" % (HOST, PORT)

    names = sorted(k.lower() for k in headers)
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)

    canonical = "%s\n%s\n%s\n%s\n%s\n%s" % (
        method, path, query,
        "".join("%s:%s\n" % (n, headers[n]) for n in names),
        ";".join(names), payload)

    scope = "%s/%s/s3/aws4_request" % (day, REGION)
    toSign = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
        amzDate, scope, hashlib.sha256(canonical.encode()).hexdigest())

    key = ("AWS4" + SECRET).encode()
    for piece in (day, REGION, "s3", "aws4_request"):
        key = hmac.new(key, piece.encode(), hashlib.sha256).digest()

    headers["authorization"] = (
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
        % (ACCESS, scope, ";".join(names),
           hmac.new(key, toSign.encode(), hashlib.sha256).hexdigest()))

    return headers


class ShortBody(Exception):
    """A 2xx whose body did not match the length it announced."""


def call(conn, method, path, body=b"", extra=None):
    """One request on a kept-alive connection. Returns (status, bytes read)."""

    headers = dict(extra or {})
    headers["content-length"] = str(len(body))
    sign(method, path, headers, "UNSIGNED-PAYLOAD")

    conn.request(method, path, body=body or None, headers=headers)
    answer = conn.getresponse()

    seen = 0
    while True:
        piece = answer.read(1 << 16)
        if not piece:
            break
        seen += len(piece)

    """
    A body that stops short of its own Content-Length is a wrong answer.

    Counting it as a success is how a benchmark misses the very thing it was
    written to find: a read that failed halfway through still has a 200 on it,
    and the bytes that never came look exactly like the end of the object.
    """
    said = answer.getheader("content-length")

    if said is not None and answer.status < 300 and seen != int(said):
        raise ShortBody("%d of %s bytes" % (seen, said))

    return answer.status, seen


def seed():
    """The objects the readers will read, one connection, before the clock."""

    conn = HTTPConnection(HOST, PORT, timeout=20)
    call(conn, "PUT", "/" + BUCKET)

    for at in range(POPULATION):
        name = SIZES[at % len(SIZES)][0]
        status, _ = call(conn, "PUT", "/%s/%s-%d.bin" % (BUCKET, name, at),
                         BODIES[name])
        if status >= 300:
            raise SystemExit("  seeding %s-%d gave %d" % (name, at, status))

    conn.close()


class Tally:
    def __init__(self):
        self.lock = threading.Lock()
        self.times = {}
        self.bytes = 0
        self.bad = 0
        self.why = {}

    def add(self, what, seconds, moved):
        with self.lock:
            self.times.setdefault(what, []).append(seconds)
            self.bytes += moved

    def fail(self, why):
        with self.lock:
            self.bad += 1
            self.why[why] = self.why.get(why, 0) + 1


def worker(tally, until, seed_):
    rng = random.Random(seed_)
    conn = HTTPConnection(HOST, PORT, timeout=20)
    mine = 0

    while time.perf_counter() < until:

        what = pick(MIX, rng)
        at = rng.randrange(POPULATION)
        name = SIZES[at % len(SIZES)][0]
        key = "/%s/%s-%d.bin" % (BUCKET, name, at)
        began = time.perf_counter()

        try:
            if what == "put":
                """
                A key of its own, not one of the ones being read.

                Clients that overwrite the very objects other clients are
                reading are a real thing but a rare one, and measuring it as
                if it were the common case says more about the benchmark than
                about the proxy. Readers read the seeded set; writers write
                their own.
                """
                mine += 1
                key = "/%s/w-%d-%d-%s.bin" % (BUCKET, seed_, mine, name)
                status, moved = call(conn, "PUT", key, BODIES[name])
                moved = len(BODIES[name])
            elif what == "get":
                status, moved = call(conn, "GET", key)
            elif what == "range":
                first = rng.randrange(0, 32768)
                status, moved = call(conn, "GET", key, extra={
                    "range": "bytes=%d-%d" % (first, first + 4095)})
            else:
                status, moved = call(conn, "GET",
                                     "/%s?list-type=2&max-keys=100" % BUCKET)
        except Exception as bad:
            tally.fail("%s %s" % (what, type(bad).__name__))
            conn.close()
            conn = HTTPConnection(HOST, PORT, timeout=20)
            continue

        if status >= 300:
            tally.fail("%s %d" % (what, status))
            continue

        tally.add(what, time.perf_counter() - began, moved)

    conn.close()


def percentile(values, share):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * share))]


print("  seeding %d objects" % POPULATION)
seed()

print("\n  %-8s %8s %9s %10s %10s %10s" %
      ("clients", "ops/s", "MB/s", "get p50", "get p95", "put p95"))

for clients in LEVELS:

    tally = Tally()
    until = time.perf_counter() + SECONDS
    began = time.perf_counter()

    threads = [threading.Thread(target=worker, args=(tally, until, n))
               for n in range(clients)]

    for one in threads:
        one.start()
    for one in threads:
        one.join()

    took = time.perf_counter() - began
    ops = sum(len(v) for v in tally.times.values())

    print("  %-8d %8.0f %9.0f %9.1fms %9.1fms %9.1fms%s"
          % (clients, ops / took, tally.bytes / took / 1e6,
             percentile(tally.times.get("get", []), 0.50) * 1000,
             percentile(tally.times.get("get", []), 0.95) * 1000,
             percentile(tally.times.get("put", []), 0.95) * 1000,
             "   %d failed: %s" % (tally.bad, ", ".join(
                 "%s x%d" % (k, v) for k, v in sorted(
                     tally.why.items(), key=lambda kv: -kv[1])[:3]))
             if tally.bad else ""))
    sys.stdout.flush()
