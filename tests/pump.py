#!/usr/bin/env python3
"""
How fast bytes actually move, with the tail left out of it.

`tests/bench.py` times a whole request, which folds three different things
into one number: getting the bytes across, and whatever the far end does
afterwards to make them durable. For comparing a proxy against the upstream
it fronts, the second part is noise - both pay it, and it swamps the part
that is actually being compared.

So this speaks HTTP itself. It stops the clock when the **last body byte has
been written to the socket**, and times the wait for the response separately.
The first number is the pipeline's throughput; the second is the far end's
commit, reported and not counted.

This only means anything against a far end that *streams*. A proxy that takes
the whole body first and works on it afterwards will empty the socket at
memory speed and do everything in the tail - `S3SEAL_ETAG=md5` reports 2.1
GB/s here and then sits for three seconds. Read the tail before believing the
rate.

    tests/pump.py <url> <access> <secret> <gigabytes>

The body is generated as it goes, so ten gigabytes costs ten gigabytes of
network and none of memory.
"""
import hashlib
import hmac
import os
import socket
import sys
import time
from urllib.parse import urlparse

url = sys.argv[1]
access = sys.argv[2]
secret = sys.argv[3]
total = int(float(sys.argv[4]) * 1024 * 1024 * 1024)

parsed = urlparse(url)
host = parsed.hostname
port = parsed.port or 80
path = parsed.path
region = "us-east-1"

CHUNK = 1024 * 1024
block = os.urandom(CHUNK)


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


headers = sign("PUT", path, {"content-length": str(total)},
               "UNSIGNED-PAYLOAD")

one = socket.create_connection((host, port))
one.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

request = "PUT %s HTTP/1.1\r\n" % path
request += "".join("%s: %s\r\n" % (k, v) for k, v in headers.items())
request += "\r\n"

one.sendall(request.encode())

began = time.perf_counter()
sent = 0

try:
    while sent < total:
        piece = min(CHUNK, total - sent)
        one.sendall(block[:piece] if piece < CHUNK else block)
        sent += piece
except BrokenPipeError:
    one.setblocking(True)
    print("  refused after %d bytes: %s" % (sent, one.recv(600).decode(
        errors="replace").replace("\r\n", " ")[:400]))
    sys.exit(1)

# the clock stops here: every byte is on the socket
moved = time.perf_counter() - began

answer = b""
while b"\r\n\r\n" not in answer:
    got = one.recv(4096)
    if not got:
        break
    answer += got

tail = time.perf_counter() - began - moved
one.close()

status = answer.split(b" ")[1].decode() if b" " in answer else "?"

if os.getenv("PUMP_LOUD"):
    print(answer.decode(errors="replace")[:700])

print("  %-28s %6.2f s  %6.0f MB/s   (danach %.2f s bis %s)"
      % (parsed.hostname + ":" + str(port), moved, total / moved / 1e6, tail,
         status))
