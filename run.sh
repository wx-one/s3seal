#!/bin/sh
#
# Starts s3seal.
#
#   ./run.sh                    with everything under ./var
#   S3SEAL_HOME=/srv ./run.sh    somewhere else
#
# On a first run it makes the master key and a credentials file and prints the
# access key. Both are 0600 and neither is ever written to tape.
#
#   S3SEAL_PORT        what to listen on (9000)
#   S3SEAL_UPSTREAM    the S3 to sit in front of
#   NGINX_BINARY      the nginx that loads the module

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
home=${S3SEAL_HOME:-$here/var}
build="$here/build"

metahttp=${META_HTTP:-/home/tobi/serious_projects/metalanguage/meta-http}
module=${S3SEAL_MODULE:-$build/nginx/objs/ngx_http_meta_module.so}
binary=${NGINX_BINARY:-/home/tobi/serious_projects/nginx/objs/nginx}

[ -f "$module" ] || { echo "no module - run ./build.sh first"; exit 2; }
[ -x "$binary" ] || { echo "no nginx at $binary"; exit 2; }
[ -x "$metahttp" ] || { echo "no meta-http at $metahttp"; exit 2; }

mkdir -p "$home" "$home/nginx"
chmod 700 "$home"

# ------------------------------------------------------------ the two secrets

if [ ! -f "$home/seed" ]; then
  echo "making a seed at $home/seed"
  ( umask 077 && openssl rand -out "$home/seed" 32 )
  chmod 600 "$home/seed"
  echo "  keep it. Without it every cartridge is noise."
fi

if [ ! -f "$home/credentials" ]; then
  access=s3seal$(openssl rand -hex 8 | tr 'a-f' 'A-F')
  secret=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)
  ( umask 077 && printf '%s %s\n' "$access" "$secret" > "$home/credentials" )
  chmod 600 "$home/credentials"
  echo "made credentials at $home/credentials"
  echo "  access key: $access"
  echo "  secret:     $secret"
fi

export S3SEAL_PORT=${S3SEAL_PORT:-9000}
export S3SEAL_SEED="$home/seed"
export S3SEAL_UPSTREAM=${S3SEAL_UPSTREAM:?set it to the S3 to sit in front of}
export S3SEAL_UPSTREAM_ACCESS=${S3SEAL_UPSTREAM_ACCESS:?}
export S3SEAL_UPSTREAM_SECRET=${S3SEAL_UPSTREAM_SECRET:?}
export S3SEAL_SCRATCH=${S3SEAL_SCRATCH:-.s3seal/uploads}
export S3SEAL_ETAG=${S3SEAL_ETAG:-md5}
export S3SEAL_CREDENTIALS="$home/credentials"
export S3SEAL_REGION=${S3SEAL_REGION:-us-east-1}
export S3SEAL_MAX_PART=${S3SEAL_MAX_PART:-16777216}

export META_HTTP_NGINX="$binary"
export META_HTTP_PREFIX="$home/nginx"

echo "s3seal on :$S3SEAL_PORT, in front of $S3SEAL_UPSTREAM"

exec "$metahttp" "$module"
