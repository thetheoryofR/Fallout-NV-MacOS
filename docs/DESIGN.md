# Design

## Why static recompilation

A hand-written decompile of a large game is a multi-year effort. A static recompiler translates
every instruction mechanically into C; it is correct wherever the lifter is correct, and a
differential tester measures exactly where that is. Readability (naming, types) is an optional
layer for debugging, not a prerequisite.

## Lifter: Ghidra P-code

Ghidra's x86 Sleigh spec already models the awkward parts as plain registers: each flag is a
1-byte register, SSE lanes are sub-registers, and the x87 stack is modelled by explicit register
shifts. The emitter is therefore a direct P-code → C translation. Things Ghidra's model leaves out,
and how the runtime restores them:

| Gap | Handling |
| :--- | :--- |
| x87 `TOP` field (not tracked; stack is shifted instead) | emitter keeps TOP per push/pop mnemonic and merges it into the status word before any read |
| unique (temp) space is byte-addressed — a 16-byte temp is read back as 4-byte slices | temps live in one per-function byte buffer with overlapping ranges merged |
| host NaN rules differ from x86 | float ops return the NaN operand (quieted), first operand wins |
| x87 80-bit precision | arithmetic in `double`; MSVC's CRT sets 53-bit precision control, so this matches the hardware as such games run |

## Runtime model

- Guest memory: a reserved 4 GB region; guest pointers stay 32-bit offsets into it. The image loads
  at its preferred base.
- One C function per guest function; intra-function branches are `goto`s; direct calls are C calls.
- Indirect calls/jumps go through a guest-address → host-function table and trap on a miss.
- Value model (M0): every value is an `unsigned __int128` of the varnode's bytes, masked per op —
  correctness first; typed narrowing is an M1 optimisation.

## Verification

`difftest.py` builds randomised machine state per trial — GPRs, flags, XMM, a stack, a
pointer-rich scratch heap, the image's writable sections — runs the original bytes in Unicorn and
the native function from it, and compares GPRs, CF/ZF/SF/OF, logical ST0, XMM0-7 and memory.
Trials where the *original* faults are invalid, not failures. Each worker is a separate process so a
native crash is attributed to one function instead of hanging the run. Sanity check before trusting
a pass rate: alter one generated function and confirm it fails.

## Milestones

- **M0 — lifter proof** (done): leaf functions, ≥95% exact.
- **M1 — whole program**: calls, virtual dispatch, switch tables, function-boundary repair.
- **M2 — boots headless**: Win32 import shims, null renderer.
- **M3 — renders**: D3D9 → Metal.
- **M4 — plays**: audio, input, video, saves.
