#!/bin/bash
# Builds s3seal against meta at /opt/meta (the wxone/meta image) and packs a
# release: nginx with the proxy built in, a start script, a systemd unit and
# the docs.
#
#   ci/build.sh [version]        writes out/s3seal-<version>-linux-x86_64.tar.gz
#
# Needs: /opt/meta (meta, its headers, lib/libmeta_runtime.a), gcc, make,
# curl, perl, xz, jq. Every library but glibc is built from pinned sources by
# ci/deps.sh and linked statically; what the release asks of a host is glibc,
# nothing else. The same on a CI runner (ubuntu-24.04) and in
# `docker run ubuntu:24.04`.
#
# The proxy is lowered by ./build.sh, as for development, and only the last
# step differs: --add-module instead of --add-dynamic-module, so the release
# is one binary with one OpenSSL in it, and nothing to load_module.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:-dev}
export META_ROOT=${META_ROOT:-/opt/meta}
export NGINX_VERSION=1.26.3
export NGINX_SHA256=69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa
export NGINX_URL=https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
NAME=s3seal-$VERSION-linux-x86_64
OUT=$PWD/out
WORK=$OUT/work
STAGE=$WORK/$NAME

[ -x "$META_ROOT/meta" ] || { echo "no meta at $META_ROOT" >&2; exit 2; }
# an installed meta (the runtime as an archive), not a checkout
"$META_ROOT/meta" -print-config | grep -q '^runtime-archive=/' \
  || { echo "meta at $META_ROOT has no runtime archive (a checkout, not an installation?)" >&2; exit 2; }
export YYJSON_H=$("$META_ROOT/meta" -print-config | sed -n 's/^vendored-yyjson=//p')

export DEPS=${DEPS:-$OUT/deps}
[ -f "$DEPS/SOURCES" ] || ci/deps.sh "$DEPS"
L=$DEPS/lib
ADDON=$PWD/build/addon

rm -rf "$WORK" && mkdir -p "$WORK" "$STAGE"

# ---------------------------------------------------------------- lower
# against the release's OpenSSL and curl headers, and with their archives on
# the module's link line - meta groups them with its runtime, so the order
# does not decide
S3SEAL_INCLUDE=$DEPS/include \
S3SEAL_LIBS="$L/libcurl.a $L/libssl.a $L/libcrypto.a $L/libz.a -lpthread -ldl" \
  ./build.sh addon >"$WORK/lower.log" 2>&1 || { cat "$WORK/lower.log" >&2; exit 1; }

# ---------------------------------------------------------------- nginx
tarball=$OUT/sources/nginx-$NGINX_VERSION.tar.gz
mkdir -p "$OUT/sources"
[ -f "$tarball" ] || curl -fsSL "$NGINX_URL" -o "$tarball"
echo "$NGINX_SHA256  $tarball" | sha256sum -c --quiet -
tar -xzf "$tarball" -C "$WORK"

(
  cd "$WORK/nginx-$NGINX_VERSION"
  # the prefix the release unpacks to; every path is also given at start.
  # No rewrite and no gzip, so nginx needs neither PCRE nor zlib of its own,
  # and no ssl module: the proxy listens plain, behind whatever terminates TLS.
  # nginx exports its symbols (-E); what comes from the archives stays inside
  # (--exclude-libs)
  ./configure --prefix=/opt/s3seal \
    --with-cc-opt="-O2 -fstack-protector-strong -I$DEPS/include" \
    --with-ld-opt="-L$L -Wl,--exclude-libs,ALL" \
    --without-http_rewrite_module --without-http_gzip_module \
    --without-http_auth_basic_module \
    --add-module="$ADDON" >"$WORK/configure.log" 2>&1 \
    || { tail -20 "$WORK/configure.log" >&2; exit 1; }
  make -j"$(nproc)" >"$WORK/make.log" 2>&1 \
    || { grep -E "error:|warning:|undefined reference|relocation" "$WORK/make.log" | head -20 >&2; exit 1; }
)

binary=$WORK/nginx-$NGINX_VERSION/objs/nginx

# nginx 1.26 builds with -Werror, so a warning stopped the build above; this
# is for one that gcc only says without failing
! grep -q "warning:" "$WORK/make.log" \
  || { grep "warning:" "$WORK/make.log" | head -10 >&2; exit 1; }
# The binary may leave open only what glibc provides; anything else would
# be a library that is not linked in
open=$(nm -D --undefined-only "$binary" \
  | awk '{print $2}' | grep -v -E '@GLIBC_|^__gmon_start__$|^_ITM_|^__cxa_finalize' || true)
[ -z "$open" ] || { echo "the binary leaves open:" >&2; echo "$open" | head -20 >&2; exit 1; }
# nor offers our libraries to anything
leaked=$(nm -D --defined-only "$binary" | awk '{print $3}' \
  | grep -E '^(EVP_|OPENSSL_|SSL_|curl_|deflate|inflate)' | head -5 || true)
[ -z "$leaked" ] || { echo "the binary exports library symbols:" >&2; echo "$leaked" >&2; exit 1; }
# and it is the proxy: the module is in it, not loaded
grep -q ngx_http_meta_module "$WORK/nginx-$NGINX_VERSION/objs/ngx_modules.c" \
  || { echo "s3seal is not built into nginx" >&2; exit 1; }

# ---------------------------------------------------------------- pack
mkdir -p "$STAGE/sbin" "$STAGE/bin"
cp "$binary" "$STAGE/sbin/nginx"
cp ci/s3seal "$STAGE/bin/s3seal"
chmod +x "$STAGE/bin/s3seal"
cp ci/s3seal.service README.md LICENSE "$STAGE/"

# yyjson only where the meta runtime's json made it into the binary
yyjson=
if nm "$binary" | grep -q ' yyjson_'; then
  yyjson=$(sed -n 's/^#define YYJSON_VERSION_STRING "\(.*\)"/\1/p' "$YYJSON_H")
fi
export YYJSON_VERSION=$yyjson

# the licence of everything inside, as the licences ask: nginx, and the
# libraries from their sources
{
  echo "s3seal $VERSION contains the following third-party software."
  echo "Each is listed with its licence, as found in the source it was built from."
  section() { printf '\n\n================================================================\n%s\n================================================================\n\n' "$1"; }
  section "nginx $NGINX_VERSION (BSD-2-Clause)"
  cat "$WORK/nginx-$NGINX_VERSION/LICENSE"
  while read -r name version url sum; do
    section "$name $version"
    cat "$DEPS/licenses/$name"
  done < "$DEPS/SOURCES"
  if [ -n "$yyjson" ]; then
    section "yyjson $yyjson (MIT), vendored in the meta runtime"
    sed -n '2,20p' "$YYJSON_H"
  fi
  section "glibc (LGPL-2.1-or-later)"
  echo "Not included: linked dynamically and provided by the host system."
} > "$STAGE/THIRD_PARTY_NOTICES"

{
  echo "s3seal $VERSION"
  echo "commit $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "nginx $NGINX_VERSION"
  echo "meta $("$META_ROOT/meta" --version | cut -d" " -f2) (${META_REF:-image unknown})"
  while read -r name version url sum; do echo "$name $version"; done < "$DEPS/SOURCES"
  echo "built on $(. /etc/os-release && echo "$PRETTY_NAME")"
} > "$STAGE/BUILD"

ci/sbom.sh release "$STAGE" "$VERSION" > "$OUT/$NAME.cdx.json"
cp "$OUT/$NAME.cdx.json" "$STAGE/SBOM.cdx.json"

tar -czf "$OUT/$NAME.tar.gz" -C "$WORK" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" "$NAME.cdx.json" > "$NAME.sha256")
echo "$OUT/$NAME.tar.gz"
