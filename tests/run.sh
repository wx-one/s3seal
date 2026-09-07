#!/bin/sh
#
# The format, on its own. No network, no proxy, no upstream.
#
#   tests/run.sh

set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
meta=${META:-/home/tobi/serious_projects/metalanguage/meta}
runtime=${META_RUNTIME:-/home/tobi/serious_projects/metalanguage/runtime/include}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for name in s3seal util frame config sigv4; do
  [ -f "$here/src/$name.h" ] || continue
  "$meta" -s -emit "$work/$name.h" -I "$here/src" -I "$runtime" \
      "$here/src/$name.h" >"$work/$name.h.log" 2>&1 || {
    echo "lowering $name.h failed"; sed -n '1,10p' "$work/$name.h.log"; exit 1; }
done

for name in util frame config sigv4; do
  "$meta" -s -emit "$work/$name.c" -I "$here/src" -I "$runtime" \
      "$here/src/$name.c" >"$work/$name.c.log" 2>&1 || {
    echo "lowering $name.c failed"; sed -n '1,10p' "$work/$name.c.log"; exit 1; }
done

"$meta" -s -emit "$work/unit.c" -I "$here/src" -I "$runtime" \
    "$here/tests/unit.c" >"$work/unit.log" 2>&1 || {
  echo "lowering unit.c failed"; sed -n '1,10p' "$work/unit.log"; exit 1; }

cc -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE -O2 -I"$work" \
    -o "$work/unit" "$work/unit.c" "$work/util.c" "$work/frame.c" \
    -lcrypto 2>"$work/build.log" || {
  echo "the format would not compile"
  sed -n '1,20p' "$work/build.log"
  exit 1
}

"$work/unit" "$work"
