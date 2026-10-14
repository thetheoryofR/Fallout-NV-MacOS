# byog-recomp — bring-your-own-game static recompiler for 32-bit x86

Translates the machine code of a 32-bit Windows (x86) game into C that compiles natively for
Apple Silicon (arm64), and **proves each translated function correct** by running the original
instructions in an emulator from the same randomised state and comparing every register, flag and
byte of memory.

**This repository contains no game code, no game data and nothing derived from any game.** You
supply an executable you own; everything the tools produce from it stays on your machine.

## Status

Milestone 0 (lifter proof), measured on the leaf functions of one 2010 PC RPG (3.5 M instructions,
63k functions):

| | functions |
| :--- | ---: |
| leaf functions translated | 9,710 of 9,866 |
| match the original exactly (6 random trials each) | **8,767 of 8,830 testable (99.3%)** |
| differ only in CPU flags | 36 |
| fail | 27 |
| crash | 0 |

Next: whole-program translation (calls, C++ virtual dispatch, switch tables), then OS/graphics
shims. See [`docs/DESIGN.md`](docs/DESIGN.md).

## How it works

1. **Ghidra** analyses the executable. Its Sleigh processor model turns every x86 instruction into
   *P-code*, a small, precise intermediate language (flags, x87 stack and SSE lanes included).
2. `ghidra_scripts/DumpPcode.java` exports that P-code per function.
3. `recomp/emit.py` translates P-code mechanically into C over a register file and a 4 GB guest
   address space (`recomp/rt.h`).
4. `recomp/build.sh` compiles it with clang into a native library.
5. `recomp/difftest.py` runs each function both ways — natively, and as the original bytes in the
   [Unicorn](https://www.unicorn-engine.org/) emulator — from identical random state and reports
   pass / fail / flags-only / untestable per function.

## Bring your own game

- You need a **legally owned, unencrypted** 32-bit Windows executable. DRM-wrapped executables are
  out of scope for this project; DRM-free releases work directly.
- Keep everything the tools generate (Ghidra project, P-code dumps, generated C, built libraries)
  **outside this repository**. The `.githooks/pre-commit` guard refuses to commit executables,
  DLLs, Ghidra projects, P-code dumps and generated C; enable it with
  `git config core.hooksPath .githooks`.
- Do not publish generated output. It is a translation of the game's code and belongs to its owner.

## Requirements

macOS on Apple Silicon, Ghidra 12 (`brew install ghidra`), clang, Python 3.9+ with
`unicorn>=2.1.4` and `numpy` (`pip install -r requirements.txt`). Unicorn 2.1.1 crashes on recent
macOS — use 2.1.4 or newer.

## Quick start

```bash
GAME=/path/to/your/game.exe          # your own copy
WORK=/path/outside/this/repo
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
HEADLESS=$(brew --prefix ghidra)/libexec/support/analyzeHeadless

# 1. analyse + dump P-code for leaf functions
$HEADLESS "$WORK/ghidra" game -import "$GAME"
$HEADLESS "$WORK/ghidra" game -process -noanalysis -readOnly \
    -scriptPath ghidra_scripts -postScript DumpPcode.java "$WORK/leaf.jsonl" leaf

# 2. translate, build, verify
python3 recomp/emit.py "$WORK/leaf.jsonl" "$WORK/gen"
recomp/build.sh "$WORK/gen" "$WORK/build"
python3 recomp/difftest.py "$GAME" "$WORK/build/librecomp.dylib" "$WORK/leaf.jsonl.regs.json" \
    "$WORK/difftest.json"
```

## Other scripts

- `SourceFileTagger.java` — names functions after the source files their assert strings mention.
- `ExportDecomp.java` — exports Ghidra's decompiled C grouped by those source files (local study).
- `ControlFlowStats.java`, `Stats.java` — recompilation-difficulty census.

## Prior art

N64Recomp, XenonRecomp and ReXGlue (PowerPC) established the bring-your-own-game static
recompilation model this project follows for x86.

## Licence

MIT — see [`LICENSE`](LICENSE). Covers this repository's code only.
