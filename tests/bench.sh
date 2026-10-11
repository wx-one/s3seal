#!/bin/sh
#
# What the sealing costs. Starts an upstream and the proxy, measures both.
#
#   tests/bench.sh            64 MB
#   tests/bench.sh 256        bigger
#
# As tests/proxy.sh: MINIO_BINARY for a MinIO that is not a container, and
# S3SEAL_RELEASE for an unpacked release instead of ./build.sh's module.
# S3SEAL_ETAG=opaque is what streams an upload through the sealing stage;
# S3SEAL_TIMING=1 prints where that stage's time went.

set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$here/build"
binary=${NGINX_BINARY:-$here/../nginx/objs/nginx}

port=${S3SEAL_BENCH_PORT:-9561}
upstreamPort=${S3SEAL_BENCH_UPSTREAM_PORT:-9562}
container=s3seal-bench-minio
megabytes=${1:-64}

if [ -z "${MINIO_BINARY:-}" ]; then
  command -v docker >/dev/null 2>&1 || { echo "no docker"; exit 1; }
fi
[ -n "${S3SEAL_RELEASE:-}" ] || [ -f "$build/nginx/objs/ngx_http_meta_module.so" ] || {
  echo "no module - run ./build.sh"; exit 1; }

work=$(mktemp -d)
home="$work/home"
mkdir -p "$home"

stop() {
  for pid in "$home/nginx/logs/meta.pid" "$home/logs/meta.pid"; do
    [ -f "$pid" ] && kill "$(cat "$pid" 2>/dev/null)" 2>/dev/null
  done
  if [ -n "${upstreamPid:-}" ]; then
    kill "$upstreamPid" 2>/dev/null
  else
    docker rm -f "$container" >/dev/null 2>&1
  fi
  sleep 1
  rm -rf "$work"
}

trap stop EXIT

if [ -n "${MINIO_BINARY:-}" ]; then
  mkdir -p "$work/minio"
  MINIO_ROOT_USER=benchuser MINIO_ROOT_PASSWORD=benchpass123 \
      "$MINIO_BINARY" server --address "127.0.0.1:$upstreamPort" \
      "$work/minio" >"$work/minio.log" 2>&1 &
  upstreamPid=$!
else
  docker rm -f "$container" >/dev/null 2>&1
  docker run -d --rm --name "$container" -p "$upstreamPort:9000" \
      -e MINIO_ROOT_USER=benchuser -e MINIO_ROOT_PASSWORD=benchpass123 \
      quay.io/minio/minio server /data >/dev/null 2>&1
fi

waited=0
while [ "$waited" -lt 60 ]; do
  curl -s -o /dev/null "http://127.0.0.1:$upstreamPort/minio/health/live" &&
      break
  sleep 0.5
  waited=$((waited + 1))
done

[ "$waited" -ge 60 ] && { echo "the upstream never came up"; exit 1; }

# the part limit is raised so a single PUT of the benchmark object fits
export S3SEAL_PORT="$port"
export S3SEAL_UPSTREAM="http://127.0.0.1:$upstreamPort"
export S3SEAL_UPSTREAM_ACCESS=benchuser S3SEAL_UPSTREAM_SECRET=benchpass123
export S3SEAL_MAX_PART=$((megabytes * 1024 * 1024 + 1048576))
export S3SEAL_ETAG="${S3SEAL_ETAG:-md5}"

if [ -n "${S3SEAL_RELEASE:-}" ]; then
  S3SEAL_STATE_DIR="$home" "$S3SEAL_RELEASE/bin/s3seal" >"$work/server.log" 2>&1 &
else
  S3SEAL_HOME="$home" "$here/run.sh" >"$work/server.log" 2>&1 &
fi

waited=0
while [ "$waited" -lt 60 ]; do
  curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
  sleep 0.25
  waited=$((waited + 1))
done

[ "$waited" -ge 60 ] && {
  echo "the proxy never answered"
  sed -n '1,20p' "$work/server.log"
  exit 1
}

PROXY_KEY=$(awk '{print $1}' "$home/credentials")
PROXY_SECRET=$(awk '{print $2}' "$home/credentials")
export PROXY_KEY PROXY_SECRET
export UPSTREAM_KEY=benchuser UPSTREAM_SECRET=benchpass123

printf 'upstream: MinIO in a container on loopback, ETag=%s\n' "${S3SEAL_ETAG:-md5}"

"$here/tests/bench.py" "http://127.0.0.1:$port" \
    "http://127.0.0.1:$upstreamPort" "$megabytes"

[ -z "${S3SEAL_TIMING:-}" ] || grep -h 'bytes - begin' "$work/server.log"
