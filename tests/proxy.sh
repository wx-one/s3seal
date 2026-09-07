#!/bin/sh
#
# s3seal end to end: the real nginx, the real module, a real S3 behind it and
# real S3 clients in front.
#
#   tests/proxy.sh
#
# The upstream is a MinIO in a container, started here and stopped on the way
# out. What is checked is not that the proxy answers - it is that the object
# on the upstream is *not* the object the client sent, and that the client
# cannot tell.

set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$here/build"
binary=${NGINX_BINARY:-/home/tobi/serious_projects/nginx/objs/nginx}

port=${S3SEAL_TEST_PORT:-9557}
upstreamPort=${S3SEAL_TEST_UPSTREAM_PORT:-9558}
container=s3seal-test-minio

failed=0
ran=0

say() { printf '%s\n' "$*"; }

check() {
  ran=$((ran + 1))
  if [ "$2" = "$3" ]; then
    say "ok       $1"
  else
    say "FAIL     $1"
    say "  wanted: $3"
    say "  got:    $2"
    failed=$((failed + 1))
  fi
}

same() {
  ran=$((ran + 1))
  if cmp -s "$2" "$3"; then
    say "ok       $1"
  else
    say "FAIL     $1"
    failed=$((failed + 1))
  fi
}

command -v docker >/dev/null 2>&1 || { say "skipped: no docker"; exit 0; }
command -v aws >/dev/null 2>&1 || { say "skipped: no aws cli"; exit 0; }
[ -x "$binary" ] || { say "skipped: no nginx at $binary"; exit 0; }
[ -f "$build/nginx/objs/ngx_http_meta_module.so" ] || {
  say "skipped: no module - run ./build.sh"; exit 0; }

work=$(mktemp -d)
home="$work/home"
mkdir -p "$home"

stop() {
  [ -f "$home/nginx/logs/meta.pid" ] &&
      kill "$(cat "$home/nginx/logs/meta.pid" 2>/dev/null)" 2>/dev/null
  docker rm -f "$container" >/dev/null 2>&1
  sleep 1
  [ -n "${S3SEAL_TEST_KEEP:-}" ] || rm -rf "$work"
}

trap stop EXIT

# ------------------------------------------------------------- the upstream

docker rm -f "$container" >/dev/null 2>&1

docker run -d --rm --name "$container" -p "$upstreamPort:9000" \
    -e MINIO_ROOT_USER=sealtest -e MINIO_ROOT_PASSWORD=sealtest123 \
    quay.io/minio/minio server /data >/dev/null 2>&1

waited=0
while [ "$waited" -lt 60 ]; do
  curl -s -o /dev/null "http://127.0.0.1:$upstreamPort/minio/health/live" &&
      break
  sleep 0.5
  waited=$((waited + 1))
done

[ "$waited" -ge 60 ] && { say "the upstream never came up"; exit 1; }

say "ok       an upstream S3 is running"
ran=$((ran + 1))

# ---------------------------------------------------------------- the proxy

S3SEAL_HOME="$home" S3SEAL_PORT="$port" \
    S3SEAL_UPSTREAM="http://127.0.0.1:$upstreamPort" \
    S3SEAL_UPSTREAM_ACCESS=sealtest S3SEAL_UPSTREAM_SECRET=sealtest123 \
    "$here/run.sh" >"$work/server.log" 2>&1 &

waited=0
while [ "$waited" -lt 60 ]; do
  curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
  sleep 0.25
  waited=$((waited + 1))
done

[ "$waited" -ge 60 ] && {
  say "the proxy never answered"
  sed -n '1,20p' "$work/server.log"
  exit 1
}

say "ok       the proxy started"
ran=$((ran + 1))

AWS_ACCESS_KEY_ID=$(awk '{print $1}' "$home/credentials")
AWS_SECRET_ACCESS_KEY=$(awk '{print $2}' "$home/credentials")
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true

# A part has to be a whole number of 64 KiB frames - see frame.h - and the
# CLI's newer transfer manager picks an adaptive size that is not. Every round
# default (5, 8, 16 MiB) is one, so this is a line of configuration rather
# than a limitation, but it has to be said out loud.
printf '[default]\ns3 =\n  multipart_chunksize = 8MB\n  multipart_threshold = 8MB\n  preferred_transfer_client = classic\n' \
    > "$work/aws-config"

export AWS_CONFIG_FILE="$work/aws-config"
export AWS_SHARED_CREDENTIALS_FILE="$work/aws-credentials"

s3() { aws --endpoint-url "http://127.0.0.1:$port" "$@" 2>>"$work/aws.log"; }
# straight to the upstream, with *its* credentials - the whole point being
# that these two identities are different and the client never has both
raw() { AWS_ACCESS_KEY_ID=sealtest AWS_SECRET_ACCESS_KEY=sealtest123 \
        aws --endpoint-url "http://127.0.0.1:$upstreamPort" "$@" \
            2>>"$work/aws.log"; }

# --------------------------------------------------------------- refusing

check "an unsigned request is refused" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" "403"

check "a wrong secret is refused" \
    "$(AWS_SECRET_ACCESS_KEY=wrongwrongwrong aws \
         --endpoint-url "http://127.0.0.1:$port" s3 ls 2>&1 |
       grep -c SignatureDoesNotMatch)" "1"

# ---------------------------------------------------------------- an object

s3 s3 mb s3://sealed >/dev/null
check "a bucket is made through the proxy" "$?" "0"

head -c 100000 /dev/urandom > "$work/a.bin"

s3 s3 cp "$work/a.bin" s3://sealed/a.bin >/dev/null
check "an object goes up" "$?" "0"

s3 s3 cp s3://sealed/a.bin "$work/a.back" >/dev/null
same "and comes back byte for byte" "$work/a.bin" "$work/a.back"

# only in the mode that promises it. Opaque ETags exist so that nothing in
# the upstream's headers depends on bytes that have not arrived yet, which is
# what lets receiving and sending overlap - see config.h.
if [ "${S3SEAL_ETAG:-md5}" = "md5" ]; then
  check "and its ETag is the plaintext MD5" \
      "$(s3 s3api head-object --bucket sealed --key a.bin \
           --query ETag --output text | tr -d '\"')" \
      "$(md5sum "$work/a.bin" | cut -d' ' -f1)"
else
  check "and its ETag is the upstream's, not the plaintext MD5" \
      "$(s3 s3api head-object --bucket sealed --key a.bin \
           --query ETag --output text | tr -d '\"' |
         grep -qx "$(md5sum "$work/a.bin" | cut -d' ' -f1)" && echo same ||
         echo other)" "other"
fi

check "and its length is the plaintext length" \
    "$(s3 s3api head-object --bucket sealed --key a.bin \
         --query ContentLength --output text)" "100000"

# ------------------------------------------------- and what is really stored

raw s3 cp s3://sealed/a.bin "$work/a.raw" >/dev/null

check "the upstream holds more bytes than the client sent" \
    "$([ "$(stat -c%s "$work/a.raw")" -gt 100000 ] && echo more || echo no)" \
    "more"

ran=$((ran + 1))
if cmp -s "$work/a.bin" "$work/a.raw"; then
  say "FAIL     and they are not the client's bytes"
  failed=$((failed + 1))
else
  say "ok       and they are not the client's bytes"
fi

check "the client's first bytes appear nowhere in it" \
    "$(head -c 48 "$work/a.bin" > "$work/needle";
       grep -c -aF -f /dev/null "$work/a.raw" 2>/dev/null;
       if grep -qaF "$(head -c 24 "$work/a.bin")" "$work/a.raw" 2>/dev/null
       then echo found; else echo absent; fi)" "absent"

# it can see the *wrapped* key and that is all it can do with it: the wrapping
# key is derived from a seed the upstream has never been told
check "the upstream holds only a wrapped key" \
    "$(raw s3api head-object --bucket sealed --key a.bin \
         --query 'Metadata.seal' --output text | tr -d '\n' | wc -c |
       tr -d ' ')" "120"

# ----------------------------------------------------------------- ranges

sig="--aws-sigv4 aws:amz:us-east-1:s3 -u $AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"

# shellcheck disable=SC2086
curl -s $sig -H "Range: bytes=1000-1999" -o "$work/r1" \
    "http://127.0.0.1:$port/sealed/a.bin"
dd if="$work/a.bin" bs=1 skip=1000 count=1000 of="$work/r1.want" 2>/dev/null
same "a range inside one frame is right" "$work/r1" "$work/r1.want"

# 65536 is a frame boundary, so this one spans two
# shellcheck disable=SC2086
curl -s $sig -H "Range: bytes=65000-66999" -o "$work/r2" \
    "http://127.0.0.1:$port/sealed/a.bin"
dd if="$work/a.bin" bs=1 skip=65000 count=2000 of="$work/r2.want" 2>/dev/null
same "and one that crosses a frame boundary" "$work/r2" "$work/r2.want"

# shellcheck disable=SC2086
curl -s $sig -H "Range: bytes=99990-99999" -o "$work/r3" \
    "http://127.0.0.1:$port/sealed/a.bin"
dd if="$work/a.bin" bs=1 skip=99990 count=10 of="$work/r3.want" 2>/dev/null
same "and the last ten bytes" "$work/r3" "$work/r3.want"

# ---------------------------------------------------------------- listings

check "a listing reports the plaintext size" \
    "$(s3 s3 ls s3://sealed/ | awk '{print $3}')" "100000"

check "and the upstream reports the sealed one" \
    "$(raw s3 ls s3://sealed/ | awk '{print $3}')" "100050"

# -------------------------------------------------------------- an empty one

: > "$work/empty.bin"
s3 s3 cp "$work/empty.bin" s3://sealed/empty.bin >/dev/null
s3 s3 cp s3://sealed/empty.bin "$work/empty.back" >/dev/null
same "an empty object survives the round trip" "$work/empty.bin" \
    "$work/empty.back"

# ---------------------------------------------------- one exactly a frame long

head -c 65536 /dev/urandom > "$work/frame.bin"
s3 s3 cp "$work/frame.bin" s3://sealed/frame.bin >/dev/null
s3 s3 cp s3://sealed/frame.bin "$work/frame.back" >/dev/null
same "and one that is exactly one frame" "$work/frame.bin" "$work/frame.back"

# --------------------------------------------------------------- multipart
#
# 20 MB with an 8 MiB chunk size, which is what `aws s3 cp` does by itself.
# Three parts, sealed apart, parked on the upstream and put together there.

head -c 20000000 /dev/urandom > "$work/big.bin"

s3 s3 cp "$work/big.bin" s3://sealed/big.bin >/dev/null
check "a 20 MB object goes up as a multipart upload" "$?" "0"

s3 s3 cp s3://sealed/big.bin "$work/big.back" >/dev/null
same "and comes back byte for byte" "$work/big.bin" "$work/big.back"

check "and its ETag has the part count on it" \
    "$(s3 s3api head-object --bucket sealed --key big.bin \
         --query ETag --output text | grep -c -- '-3')" "1"

check "and its length is the plaintext length" \
    "$(s3 s3api head-object --bucket sealed --key big.bin \
         --query ContentLength --output text)" "20000000"

# shellcheck disable=SC2086
curl -s $sig -H "Range: bytes=8388600-8388620" -o "$work/r4" \
    "http://127.0.0.1:$port/sealed/big.bin"
dd if="$work/big.bin" bs=1 skip=8388600 count=21 of="$work/r4.want" 2>/dev/null
same "a range across a part boundary is right" "$work/r4" "$work/r4.want"

check "and the parked parts were cleaned up" \
    "$(raw s3 ls --recursive s3://sealed/ | grep -c '.s3seal')" "0"

check "and a listing does not show the proxy's own prefix" \
    "$(s3 s3 ls --recursive s3://sealed/ | grep -c '.s3seal')" "0"

# ---------------------------------------------------------------- deleting

s3 s3 rm s3://sealed/a.bin >/dev/null
check "an object is deleted" "$?" "0"

check "and reading it back is a 404" \
    "$(aws --endpoint-url "http://127.0.0.1:$port" s3api head-object \
         --bucket sealed --key a.bin 2>&1 | grep -c '404')" "1"

say ""
say "$ran run, $failed failed"

[ "$failed" -eq 0 ]
