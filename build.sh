#!/bin/sh
#
# Lowers s3seal with meta and builds it into an nginx dynamic module.
#
#   ./build.sh              lower, build the module
#   ./build.sh test         and then run the tests
#   ./build.sh clean        throw the build directory away
#
# Where things are, all overridable:
#
#   META             the meta binary
#   META_RUNTIME     meta's runtime include directory
#   NGINX_SOURCE     an nginx *source tree* of the same version as the binary
#   NGINX_BINARY     the nginx that will load the module
#
# ------------------------------------------------------------------ two notes
#
# **The source tree is copied, not configured in place.** nginx's configure
# writes `Makefile` and `objs/` into the tree it is pointed at, and a tree
# somebody is already using for something else is not ours to overwrite. The
# copy is six megabytes and takes a moment.
#
# **The `-D` list is passed to meta and to the C compiler both.** meta expands
# macros while lexing and does not write them back, so a `#define` in a source
# file is gone from the C it emits. Anything that has to mean the same thing to
# both - which is every `META_HTTP_*` size below - has to be on both command
# lines. There is one list, here, and that is the whole reason it is here.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build="$here/build"
addon="$build/addon"

meta=${META:-/home/tobi/serious_projects/metalanguage/meta}
runtime=${META_RUNTIME:-/home/tobi/serious_projects/metalanguage/runtime/include}
source=${NGINX_SOURCE:-/home/tobi/serious_projects/nginx}
binary=${NGINX_BINARY:-$source/objs/nginx}

# ---------------------------------------------------------------- the sizes
#
# S3's own limits, in meta_http's terms. A key may be 1024 bytes and go many
# segments deep, and the router splits a path into a fixed number of them -
# past which a `*key` tail would come back cut short, which is an object
# quietly stored under the wrong name.
defines="-D META_HTTP_SEGMENTS=64 \
         -D META_HTTP_SCRATCH=8192 \
         -D META_HTTP_HEADERS=64 \
         -D META_HTTP_ROUTES=64"

cdefines="-DMETA_HTTP_SEGMENTS=64 \
          -DMETA_HTTP_SCRATCH=8192 \
          -DMETA_HTTP_HEADERS=64 \
          -DMETA_HTTP_ROUTES=64"

# Every unit but the one with `main` in it. `-module` handles that one,
# because it has to land in the addon directory under its own name.
units="util frame config sigv4 sign proxy s3"
headers="s3seal util frame config sigv4 sign proxy s3"

say() { printf '%s\n' "$*"; }

if [ "${1:-}" = "clean" ]; then
  rm -rf "$build"
  say "gone"
  exit 0
fi

[ -x "$meta" ] || { say "no meta at $meta"; exit 2; }
[ -f "$source/src/core/nginx.h" ] || { say "no nginx source at $source"; exit 2; }

mkdir -p "$addon"

# ------------------------------------------------------------------ lowering
#
# Headers first, so that each source lowers against the *lowered* form of
# what it includes rather than against the metalang one - a `#include "x.h"`
# comes through unchanged, so what the C compiler reads afterwards has to be
# the lowered header sitting beside it.

say "lowering"

for name in $headers; do
  "$meta" -s -emit "$addon/$name.h" -I "$here/src" -I "$runtime" $defines \
      "$here/src/$name.h" >"$build/$name.h.log" 2>&1 || {
    say "  FAILED on src/$name.h"
    sed -n '1,10p' "$build/$name.h.log"
    exit 1
  }
done

for name in $units; do
  "$meta" -s -emit "$addon/$name.c" -I "$here/src" -I "$runtime" $defines \
      "$here/src/$name.c" >"$build/$name.c.log" 2>&1 || {
    say "  FAILED on src/$name.c"
    sed -n '1,10p' "$build/$name.c.log"
    exit 1
  }
done

# `-module` writes three files: the lowered program, the nginx module around
# it, and the `config` nginx's --add-dynamic-module reads.
"$meta" -s -module "$addon" -I "$here/src" -I "$runtime" $defines \
    "$here/src/main.c" >"$build/main.log" 2>&1 || {
  say "  FAILED on src/main.c"
  sed -n '1,10p' "$build/main.log"
  exit 1
}

for wanted in main.c ngx_http_meta_module.c config; do
  [ -f "$addon/$wanted" ] || { say "meta -module did not write $wanted"; exit 1; }
done

# ------------------------------------------------------------- the addon config
#
# meta writes a config for a program that is one unit and needs libpq. Ours is
# nine units and needs libcrypto and does not touch postgres, so the three
# lines that say so are rewritten. Rewritten rather than replaced wholesale,
# because the parts naming meta's own runtime sources are meta's to change.

say "adjusting the addon config"

ours=""
for name in $units; do
  ours="$ours \$ngx_addon_dir/$name.c"
done

awk -v ours="$ours" -v cdefines="$cdefines" '
  /ngx_module_srcs=/ { sub(/ngx_http_meta_module\.c/, "ngx_http_meta_module.c" ours) }
  /ngx_module_libs=/ { sub(/-lpq/, "-lcrypto -lcurl") }
  /ngx_module_incs=/ { sub(/"$/, " $ngx_addon_dir\"") }
  /\. auto\/module/  { print "    CFLAGS=\"$CFLAGS " cdefines "\"" }
  { print }
' "$addon/config" > "$addon/config.new"

mv "$addon/config.new" "$addon/config"

# ------------------------------------------------------------------ nginx
#
# A copy of the source tree, because configure writes into the one it is
# pointed at, and the same configure arguments the binary was built with -
# NGX_MODULE_SIGNATURE is about thirty-five bits of exactly those, and a
# module that disagrees on one of them is refused at load with a message that
# says only "not binary compatible".

if [ ! -d "$build/nginx" ]; then
  say "copying the nginx source ($(basename "$source"))"
  mkdir -p "$build/nginx"
  # `configure` at the top is the release tarball's layout; a checkout of
  # nginx's own repository has `auto/configure` and nothing at the top.
  ( cd "$source" && tar cf - auto conf src \
        $([ -f configure ] && echo configure) \
        $([ -d contrib ] && echo contrib) \
        $([ -d docs ] && echo docs) \
        $([ -d misc ] && echo misc) ) |
      ( cd "$build/nginx" && tar xf - )
fi

was=$(sed -n 's/.*#define NGX_CONFIGURE "\(.*\)"/\1/p' \
        "$source/objs/ngx_auto_config.h" 2>/dev/null || true)

if [ -z "$was" ]; then
  was="--with-compat"
  say "the nginx binary does not say how it was configured - guessing --with-compat"
fi

say "configuring nginx"

configure=./configure
[ -f "$build/nginx/configure" ] || configure=auto/configure

( cd "$build/nginx" &&
  # shellcheck disable=SC2086
  $configure $was --add-dynamic-module="$addon" ) \
    >"$build/configure.log" 2>&1 || {
  say "  configure FAILED"
  tail -20 "$build/configure.log"
  exit 1
}

say "building the module"

# nginx's Makefile does not know that meta's headers are dependencies of the
# module, so the object is removed rather than trusted to be out of date.
rm -f "$build"/nginx/objs/addon/*/*.o "$build"/nginx/objs/*.so

( cd "$build/nginx" && make modules -j"$(nproc 2>/dev/null || echo 4)" ) \
    >"$build/make.log" 2>&1 || {
  say "  build FAILED"
  grep -E "error:|Error" "$build/make.log" | head -20
  exit 1
}

module="$build/nginx/objs/ngx_http_meta_module.so"

[ -f "$module" ] || { say "no module came out"; exit 1; }

say ""
say "module: $module"
say "nginx:  $binary"
say ""
say "  NGINX_BINARY=$binary ./run.sh"

if [ "${1:-}" = "test" ]; then
  exec "$here/tests/run.sh"
fi
