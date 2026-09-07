#!/usr/bin/env python3
"""
One signed request against LTOS3, for the parts of the surface that are ours
rather than S3's - the tape and node admin API.

It signs with botocore, which is the point: the signature this sends is
produced by somebody else's implementation of SigV4, so a test that passes is
a check on our verifier and not on our own arithmetic repeated twice.

    tests/ask.py GET  http://127.0.0.1:9099/-/tapes
    tests/ask.py POST http://127.0.0.1:9099/-/tapes '{"barcode":"LT0001L8"}'
"""
import hashlib
import os
import sys
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

method = sys.argv[1]
url = sys.argv[2]
body = sys.argv[3].encode() if len(sys.argv) > 3 else b""

credentials = Credentials(os.environ["AWS_ACCESS_KEY_ID"],
                          os.environ["AWS_SECRET_ACCESS_KEY"])

request = AWSRequest(method=method, url=url, data=body)
request.headers["x-amz-content-sha256"] = hashlib.sha256(body).hexdigest()

if body:
    request.headers["content-type"] = "application/json"

SigV4Auth(credentials, "s3",
          os.environ.get("AWS_DEFAULT_REGION", "us-east-1")).add_auth(request)

sending = urllib.request.Request(url, data=body or None, method=method,
                                 headers=dict(request.headers))

try:
    with urllib.request.urlopen(sending) as answer:
        sys.stdout.write(answer.read().decode())
except urllib.error.HTTPError as bad:
    sys.stdout.write(bad.read().decode())
    sys.stderr.write("HTTP %d\n" % bad.code)
    sys.exit(1)
