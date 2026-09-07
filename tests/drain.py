#!/usr/bin/env python3
"""
How fast bytes come back, with the wait for the first one left out of it.

The download counterpart to `tests/pump.py`. A GET folds two things into one
number: how long the far end takes to say anything at all (it has to reach
the upstream, read a header, start a body), and how fast the body then moves.
For an object of 64 MB the first part is a large share of the whole, and for
one of 1 GB it is noise - so a single total makes a proxy look as if its
throughput depended on object size when what changed was the fixed cost's
weight.

So this reports them apart: time to the first body byte, and the rate over
everything after it. The body is discarded as it arrives, so a gigabyte
costs a gigabyte of network and none of memory.

    tests/drain.py <url> <access> <secret> [rounds]
"""
import hashlib
import hmac
import socket
import sys
import time
from urllib.parse import urlparse

url = sys.argv[1]
access = sys.argv[2]
secret = sys.argv[3]
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 3

parsed = urlparse(url)
host = parsed.hostname
port = parsed.port or 80
path = parsed.path
region = "us-east-1"


def sign(method, path, headers, payload):
    now = time.gmtime()
    amzDate = time.strftime("%Y%m%dT%H%M%SZ", now)
    day = time.strftime("%Y%m%d", now)

    headers["x-amz-date"] = amzDate
    headers["x-amz-content-sha256"] = payload
    headers["host"] = "%s:%d" % (host, port)

    names = sorted(k.lower() for k in headers)
    canonical = "%s\n%s\n\n%s\n%s\n%s" % (
        method, path,
        "".join("%s:%s\n" % (n, headers[n]) for n in names),
        ";".join(names), payload)

    scope = "%s/%s/s3/aws4_request" % (day, region)
    toSign = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
        amzDate, scope, hashlib.sha256(canonical.encode()).hexdigest())

    key = ("AWS4" + secret).encode()
    for piece in (day, region, "s3", "aws4_request"):
        key = hmac.new(key, piece.encode(), hashlib.sha256).digest()

    headers["authorization"] = (
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
        % (access, scope, ";".join(names),
           hmac.new(key, toSign.encode(), hashlib.sha256).hexdigest()))

    return headers


def once():
    """One GET. Returns (bytes, seconds to the first body byte, seconds of body)."""

    headers = sign("GET", path, {}, "UNSIGNED-PAYLOAD")

    request = "GET %s HTTP/1.1\r\n" % path
    request += "".join("%s: %s\r\n" % (k, v) for k, v in headers.items())
    request += "connection: close\r\n\r\n"

    one = socket.create_connection((host, port))
    one.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    asked = time.perf_counter()
    one.sendall(request.encode())

    # the head, and whatever body came in the same read
    rest = b""
    while b"\r\n\r\n" not in rest:
        got = one.recv(65536)
        if not got:
            raise SystemExit("  no answer at all")
        rest += got

    head, body = rest.split(b"\r\n\r\n", 1)
    status = head.split(b" ")[1].decode()
    if status[0] != "2":
        raise SystemExit("  %s: %s" % (status, body[:300].decode(errors="replace")))

    if b"transfer-encoding: chunked" in head.lower():
        raise SystemExit("  chunked, which this does not measure")

    length = 0
    for line in head.decode(errors="replace").split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1])

    first = time.perf_counter() - asked
    began = time.perf_counter()
    seen = len(body)

    while seen < length:
        got = one.recv(1 << 20)
        if not got:
            break
        seen += len(got)

    moved = time.perf_counter() - began
    one.close()
    return seen, first, moved


best = None
for round_ in range(rounds):
    seen, first, moved = once()
    rate = seen / moved / 1e6 if moved > 0 else 0
    if best is None or rate > best[0]:
        best = (rate, seen, first, moved)

rate, seen, first, moved = best
print("  %-24s %5.0f MB  %6.3f s  %6.0f MB/s   (erste bytes nach %.0f ms)"
      % (parsed.hostname + ":" + str(port), seen / 1e6, moved, rate,
         first * 1000))
