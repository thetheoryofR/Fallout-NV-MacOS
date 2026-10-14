#!/bin/bash
# Compile a gen dir (tu_*.c, stubs.c, table.c from emit.py) + the test runtime into one dylib.
#   recomp/build.sh <gen_dir> <build_dir> [opt=-O1]      (JOBS=n to limit parallelism)
set -euo pipefail
GEN="$1"; OUT="$2"; OPT="${3:--O1} ${RT_DEFS:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
export HERE OUT OPT
find "$GEN" -maxdepth 1 -name '*.c' ! -name '._*' -print0 |
  xargs -0 -P "${JOBS:-$(sysctl -n hw.ncpu)}" -I{} sh -c \
    'o="$OUT/$(basename "$1" .c).o"; [ "$o" -nt "$1" ] && [ "$o" -nt "$HERE/rt.h" ] || clang $OPT -fPIC -w -I"$HERE" -c "$1" -o "$o"' _ {}
clang $OPT -fPIC -I"$HERE" -c "$HERE/rt_test.c" -o "$OUT/rt_test.o"
clang $OPT -fPIC -I"$HERE" -c "$HERE/rt_dispatch.c" -o "$OUT/rt_dispatch.o"
objs=()
while IFS= read -r -d '' o; do objs+=("$o"); done < <(find "$OUT" -maxdepth 1 -name '*.o' ! -name '._*' -print0)
clang -dynamiclib -o "$OUT/librecomp.dylib" "${objs[@]}"
echo "built $OUT/librecomp.dylib (${#objs[@]} objects)"
