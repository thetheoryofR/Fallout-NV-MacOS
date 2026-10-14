# byog-recomp — bring-your-own-game static recompiler for 32-bit x86

Translates the machine code of a 32-bit Windows (x86) game into C that compiles natively for
Apple Silicon (arm64), runs it on a native host (Win32/COM shims, Direct3D 9 → Metal, input), and **proves each translated function correct** by running the original
instructions in an emulator from the same randomised state and comparing every register, flag and
byte of memory.

> **This project is for educational and research purposes only.**
>
> **This repository does not contain any game code, game assets or anything derived from a game.
> You must provide your own legally purchased copy of Fallout: New Vegas (or any other game) to
> use it.** Nothing here works without one, and everything the tools produce from it stays on your
> machine. Piracy is not supported; please do not ask for or share game files.

## Status

**Fallout: New Vegas (PC, 2010) runs natively on Apple Silicon macOS** — no Wine or CrossOver: the
whole executable (93,500 functions) is translated ahead of time to arm64, Direct3D 9 goes to Metal,
and the game's own shaders are translated SM1-3 → Metal Shading Language at run time. (An embedded
Unicorn interpreter is only a safety net for code the analysis missed.)

- One uninterrupted, recorded hour of scripted play (Goodsprings start, travel across 13 world
  cells): no crashes, flat memory, **mean 84 fps** at 3456×1944. ~96% of time at or above 60 fps;
  the heaviest cells (2,000-2,800 draws/frame) still dip to 53-59 fps.
- Every translated function can be differential-tested against the original x86 in Unicorn.
- Not done yet: audio (DirectSound is silent), Bink video, gamepad, the fixed-function pipeline,
  NVSE / script-extender mods.

You need your own legally purchased, DRM-free copy of the game (see below). Nothing in this
repository works without it.

Milestone 0 (lifter proof) on leaf functions: 8,767 of 8,830 testable functions match the original
exactly (99.3%), 0 crashes. Design notes: [`docs/DESIGN.md`](docs/DESIGN.md).

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

## Legal

This is an unofficial, non-commercial project made for education and research into static
recompilation. It is not affiliated with, endorsed by or sponsored by Bethesda Softworks,
ZeniMax Media, Microsoft or Obsidian Entertainment. Fallout and Fallout: New Vegas are trademarks
of their respective owners, used here only to describe compatibility.

No game code, assets or generated output are or will be distributed through this repository or
its releases. Buy the game to use this project.

## Licence

MIT — see [`LICENSE`](LICENSE). Covers this repository's code only, not any game.
