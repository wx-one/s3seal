#!/bin/bash
# Builds the libraries s3seal links statically, from pinned sources: OpenSSL
# (the sealing, and the upstream over https), curl (the upstream client) and
# zlib (which both of those are built with) - everything but glibc, which
# stays dynamic (DNS and NSS work the way they do for every other program on
# the host). All with -fPIC, because they end up in nginx's module.
#
#   ci/deps.sh <prefix>       installs into <prefix>/{include,lib}, prints nothing on success
#
# Every source is checked by SHA-256. The versions are wx1-keyagent's, so the
# two releases carry the same OpenSSL and curl, and they go into the SBOM.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX=${1:?prefix}
CACHE=${DEPS_CACHE:-$PWD/out/sources}
WORK=$PREFIX/.build
JOBS=$(nproc)

# name version url sha256
SOURCES=(
  "zlib 1.3.2 https://zlib.net/zlib-1.3.2.tar.gz bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
  "openssl 3.5.9 https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
  "curl 8.22.0 https://curl.se/download/curl-8.22.0.tar.xz f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7"
)

mkdir -p "$CACHE" "$WORK" "$PREFIX/include" "$PREFIX/lib" "$PREFIX/licenses"

# keep <name> <file>: the licence text, from the source as built, for THIRD_PARTY_NOTICES
keep() { cp "$2" "$PREFIX/licenses/$1"; }

export CFLAGS="-O2 -fPIC -fstack-protector-strong"
export CPPFLAGS="-I$PREFIX/include"
export LDFLAGS="-L$PREFIX/lib"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig"

# unpack <name>: fetched once into the cache, checked, unpacked fresh
unpack() {
  local entry name version url sum file
  for entry in "${SOURCES[@]}"; do
    read -r name version url sum <<<"$entry"
    [ "$name" = "$1" ] || continue
    file=$CACHE/$(basename "$url")
    [ -f "$file" ] || curl -fsSL "$url" -o "$file"
    echo "$sum  $file" | sha256sum -c --quiet -
    rm -rf "$WORK/$name-$version"
    tar -xf "$file" -C "$WORK"
    cd "$WORK/$name-$version"
    return 0
  done
  echo "unknown source $1" >&2
  exit 1
}

log() { "$@" >"$WORK/last.log" 2>&1 || { tail -30 "$WORK/last.log" >&2; exit 1; }; }

( unpack zlib
  keep zlib LICENSE
  log ./configure --prefix="$PREFIX" --static
  log make -j"$JOBS" install )

# OPENSSLDIR is a path of its own that does not exist on the host: a static
# OpenSSL reading the distribution's openssl.cnf - written for another
# version - is how a quiet incompatibility starts. The CA file is found by
# bin/s3seal and handed over as SSL_CERT_FILE.
( unpack openssl
  keep openssl LICENSE.txt
  log ./Configure linux-x86_64 --prefix="$PREFIX" --libdir=lib \
    --openssldir=/opt/s3seal/ssl no-shared no-module no-tests no-docs \
    no-legacy no-engine no-comp zlib -fPIC
  log make -j"$JOBS"
  log make install_sw )

# only what the proxy speaks: HTTP and HTTPS through OpenSSL, nothing that
# would pull in GnuTLS, LDAP, libssh, IDN or other libraries
( unpack curl
  keep curl COPYING
  log ./configure --prefix="$PREFIX" --disable-shared --enable-static --with-pic \
    --with-openssl="$PREFIX" --with-zlib="$PREFIX" --with-ca-fallback \
    --without-ca-bundle --without-ca-path \
    --without-libpsl --without-libidn2 --without-brotli --without-zstd --without-nghttp2 \
    --without-nghttp3 --without-ngtcp2 --without-libssh2 --without-libssh --without-librtmp \
    --without-gssapi --disable-ldap --disable-ldaps --disable-dict --disable-gopher \
    --disable-imap --disable-pop3 --disable-smtp --disable-telnet --disable-tftp \
    --disable-rtsp --disable-mqtt --disable-file --disable-ftp --disable-smb --disable-ipfs \
    --disable-manual --disable-docs
  log make -j"$JOBS" install )

# nothing dynamic may be left for the linker to prefer
find "$PREFIX/lib" -name '*.so*' -delete

# what was built, for the SBOM
for entry in "${SOURCES[@]}"; do
  read -r name version url sum <<<"$entry"
  printf '%s %s %s %s\n' "$name" "$version" "$url" "$sum"
done > "$PREFIX/SOURCES"

rm -rf "$WORK"
