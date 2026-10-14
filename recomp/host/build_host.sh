#!/bin/bash
# Link the recompiled objects (from recomp/build.sh) with the native host into one executable.
#   recomp/host/build_host.sh <build_dir> <out_binary>
set -euo pipefail
B="$1"; OUT="$2"; HERE="$(cd "$(dirname "$0")" && pwd)"
objs=()
while IFS= read -r -d '' o; do objs+=("$o"); done < <(find "$B" -maxdepth 1 -name '*.o' ! -name '._*' ! -name 'rt_test.o' -print0)
mkdir -p "$B/host"
for f in "$HERE"/*.c; do clang -O1 -g -I"$HERE/.." -I/opt/homebrew/include ${RT_DEFS:-} -c "$f" -o "$B/host/$(basename "$f" .c).o"; done
for f in "$HERE"/*.m; do clang -O1 -g -fobjc-arc -I"$HERE/.." -I/opt/homebrew/include ${RT_DEFS:-} -c "$f" -o "$B/host/$(basename "$f" .m).o"; done
hobjs=()
while IFS= read -r -d '' o; do hobjs+=("$o"); done < <(find "$B/host" -name '*.o' ! -name '._*' -print0)
clang -o "$OUT" "${objs[@]}" "${hobjs[@]}" /opt/homebrew/lib/libunicorn.a -framework Metal -framework QuartzCore -framework AppKit -framework ImageIO -framework UniformTypeIdentifiers -framework CoreGraphics -framework AVFoundation -Wl,-stack_size,0x10000000
echo "linked $OUT"
