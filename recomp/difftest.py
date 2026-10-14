#!/usr/bin/env python3
"""Differential test: recompiled native functions vs the original x86 bytes run in Unicorn.

    difftest.py <exe> <lib.dylib> <regs.json> <out.json> [--trials 6] [--jobs 14] [--only 0x401020,...]

For each function in the library's table, every trial builds one randomised machine state (GPRs,
flags, XMM, a stack, a pointer-rich scratch heap, the exe image), runs both sides from it and
compares GPRs, CF/ZF/SF/OF, logical ST0 (when the x87 stack is non-empty), XMM0-7 and memory
(stack, scratch, the exe's writable sections). A trial where Unicorn faults, divides by zero or
runs out of budget is *invalid* (not a failure). A function PASSES when it has >=1 valid trial
and every valid trial matches.
"""
import argparse
import ctypes
import json
import math
import subprocess
import threading
import random
import struct
import sys
from collections import Counter

import numpy as np

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import *

IMAGE_BASE = 0x400000
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x40000
STACK, STACK_SIZE = 0x2FFF0000, 0x10000
ESP0 = STACK + 0x8000
MAGIC_RET = 0x0BADF000
BUDGET = 2_000_000
TEB = 0x7FFD0000            # fake Windows thread block (FS base); GDT for Unicorn's FS lives at +0x1000
TEB_SIZE = 0x2000
IAT_MAGIC = 0xFEE00000      # import slots point at unmapped space: calling out to the OS is "invalid"

GPRS = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
UC_GPR = dict(EAX=UC_X86_REG_EAX, ECX=UC_X86_REG_ECX, EDX=UC_X86_REG_EDX, EBX=UC_X86_REG_EBX,
              ESP=UC_X86_REG_ESP, EBP=UC_X86_REG_EBP, ESI=UC_X86_REG_ESI, EDI=UC_X86_REG_EDI)
FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "OF": 11}
CMP_FLAGS = ["CF", "ZF", "SF", "OF"]


def load_pe(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    size_of_image = struct.unpack_from("<I", d, pe + 24 + 56)[0]
    size_of_headers = struct.unpack_from("<I", d, pe + 24 + 60)[0]
    img = bytearray(size_of_image)
    img[:size_of_headers] = d[:size_of_headers]
    writable = []
    s = pe + 24 + osz
    for i in range(n):
        vs, va, rs, rp = struct.unpack_from("<IIII", d, s + i * 40 + 8)
        ch = struct.unpack_from("<I", d, s + i * 40 + 36)[0]
        img[va:va + min(rs, vs or rs)] = d[rp:rp + min(rs, vs or rs)]
        if ch & 0x80000000:  # IMAGE_SCN_MEM_WRITE
            writable.append((IMAGE_BASE + va, (max(vs, rs) + 0xFFF) & ~0xFFF))
    # import address table -> IAT_MAGIC + 4*i, identical on both sides
    imp_rva = struct.unpack_from("<I", d, pe + 24 + 96 + 8)[0]
    o, k = imp_rva, 0
    while imp_rva:
        ilt, _, _, name, iat = struct.unpack_from("<IIIII", img, o)
        if name == 0:
            break
        t = iat
        while struct.unpack_from("<I", img, t)[0]:
            struct.pack_into("<I", img, t, IAT_MAGIC + 4 * k)
            t += 4
            k += 1
        o += 20
    return bytes(img), writable


def rand_word(rng, ptr_bias=0.4):
    x = rng.random()
    if x < ptr_bias:
        return SCRATCH + 0x10000 + rng.randrange(0, 0x20000) & ~3
    if x < ptr_bias + 0.2:
        return rng.randrange(0, 17)
    if x < ptr_bias + 0.4:
        return struct.unpack("<I", struct.pack("<f", rng.uniform(-100, 100)))[0]
    return rng.getrandbits(32)


def rand_block(rng, size):
    """Same mixture as rand_word (40% scratch pointers, 20% small ints, 20% floats, 20% noise)."""
    g = np.random.default_rng(rng.getrandbits(64))
    n = size // 4
    kind = g.random(n)
    ptr = (SCRATCH + 0x10000 + g.integers(0, 0x20000, n, dtype=np.uint64)) & ~np.uint64(3)
    small = g.integers(0, 17, n, dtype=np.uint64)
    flt = g.uniform(-100, 100, n).astype(np.float32).view(np.uint32).astype(np.uint64)
    noise = g.integers(0, 2 ** 32, n, dtype=np.uint64)
    out = np.where(kind < .4, ptr, np.where(kind < .6, small, np.where(kind < .8, flt, noise)))
    return out.astype("<u4").tobytes()


def f80_to_float(mant, exp):
    sign = -1.0 if exp & 0x8000 else 1.0
    e = exp & 0x7FFF
    if e == 0 and mant == 0:
        return 0.0 * sign
    if e == 0x7FFF:
        return math.nan if (mant << 1) & ((1 << 64) - 1) else sign * math.inf
    return sign * math.ldexp(float(mant), e - 16383 - 63)


def f80_bytes_to_float(b):
    mant, exp = struct.unpack("<QH", b[:10])
    return f80_to_float(mant, exp)


def feq(a, b):
    return (math.isnan(a) and math.isnan(b)) or a == b


class Worker:
    def __init__(self, exe, lib, regs):
        self.img, self.writable = load_pe(exe)
        self.R = regs
        self.lib = ctypes.CDLL(lib)
        self.lib.rt_mem.restype = ctypes.c_void_p
        self.lib.rt_addr.restype = ctypes.c_uint32
        self.lib.rt_trap_addr.restype = ctypes.c_uint32
        self.lib.rt_run.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int64]
        self.mem = self.lib.rt_mem()
        ctypes.memmove(self.mem + IMAGE_BASE, self.img, len(self.img))
        self.cpu = (ctypes.c_uint8 * 8960)()
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mu.mem_map(IMAGE_BASE, (len(self.img) + 0xFFF) & ~0xFFF)
        self.mu.mem_write(IMAGE_BASE, self.img)
        self.mu.mem_map(SCRATCH, SCRATCH_SIZE)
        self.mu.mem_map(STACK, STACK_SIZE)
        self.mu.mem_map(TEB, TEB_SIZE)
        gdt = TEB + 0x1000
        # GDT: 1 = flat 32-bit code, 2 = flat 32-bit data, 3 = FS -> TEB. Without flat 32-bit
        # entries for CS/SS Unicorn falls back to a 16-bit stack once a GDT is loaded.
        def desc(base, limit, access, flags):
            return struct.pack("<HHBBBB", limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF, access,
                               ((limit >> 16) & 0xF) | (flags << 4), (base >> 24) & 0xFF)
        table = (b"\0" * 8 + desc(0, 0xFFFFF, 0x9B, 0xC) + desc(0, 0xFFFFF, 0x93, 0xC)
                 + desc(TEB, 0xFFF, 0x93, 0x4))
        self.mu.mem_write(gdt, table)
        self.mu.reg_write(UC_X86_REG_GDTR, (0, gdt, len(table) - 1, 0))
        self.mu.reg_write(UC_X86_REG_CS, 1 << 3)
        for seg in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
            self.mu.reg_write(seg, 2 << 3)
        self.mu.reg_write(UC_X86_REG_FS, 3 << 3)
        ctypes.memmove(self.mem + gdt, table, len(table))
        self.regions = [(SCRATCH, SCRATCH_SIZE), (STACK, STACK_SIZE), (TEB, 0x1000)] + self.writable
        self.pristine = {a: self.img[a - IMAGE_BASE:a - IMAGE_BASE + n] for a, n in self.writable}
        self.index = {self.lib.rt_addr(i): i for i in range(self.lib.rt_count())}

    def setreg(self, name, val, size=4):
        off, _ = self.R[name]
        b = val.to_bytes(size, "little")
        for k in range(size):
            self.cpu[off + k] = b[k]

    def getreg(self, name, size=None):
        off, sz = self.R[name]
        return int.from_bytes(bytes(self.cpu[off:off + (size or sz)]), "little")

    def poke(self, addr, data):
        ctypes.memmove(self.mem + addr, data, len(data))
        self.mu.mem_write(addr, data)

    def trial(self, entry, rng):
        mu = self.mu
        ctypes.memset(self.cpu, 0, 8960)
        scratch = rand_block(rng, SCRATCH_SIZE)
        stack = bytearray(rand_block(rng, STACK_SIZE))
        struct.pack_into("<I", stack, ESP0 - STACK, MAGIC_RET)
        self.poke(SCRATCH, scratch)
        self.poke(STACK, bytes(stack))
        for a, data in self.pristine.items():
            self.poke(a, data)
        teb = bytearray(0x1000)
        struct.pack_into("<IIIII", teb, 0, 0xFFFFFFFF, STACK + STACK_SIZE, STACK, 0, 0)
        struct.pack_into("<I", teb, 0x18, TEB)
        struct.pack_into("<I", teb, 0x2C, TEB + 0x800)          # TLS slot array
        tls = rand_block(rng, 0x100)
        teb[0x800:0x900] = tls
        self.poke(TEB, bytes(teb))
        self.setreg("FS_OFFSET", TEB)

        for g in GPRS:
            v = ESP0 if g == "ESP" else rand_word(rng, 0.6 if g in ("ECX", "EAX", "EDX") else 0.4)
            self.setreg(g, v)
            mu.reg_write(UC_GPR[g], v)
        eflags = 0x2
        for f, bit in FLAGS.items():
            v = rng.getrandbits(1)
            self.setreg(f, v, 1)
            eflags |= v << bit
        mu.reg_write(UC_X86_REG_EFLAGS, eflags)
        mu.reg_write(UC_X86_REG_FPCW, 0x027F)    # MSVC CRT: 53-bit precision, all masked
        self.setreg("FPUControlWord", 0x027F, 2)
        mu.reg_write(UC_X86_REG_FPSW, 0)
        mu.reg_write(UC_X86_REG_FPTAG, 0xFFFF)
        mu.reg_write(UC_X86_REG_MXCSR, 0x1F80)
        for i in range(8):
            lanes = [rand_word(rng, 0.0) for _ in range(4)]
            v = int.from_bytes(struct.pack("<4I", *lanes), "little")
            self.setreg(f"XMM{i}", v, 16)
            mu.reg_write(UC_X86_REG_XMM0 + i, v)

        try:
            mu.emu_start(entry, MAGIC_RET, count=BUDGET)
        except UcError as e:
            return "invalid", f"unicorn: {e}"
        if mu.reg_read(UC_X86_REG_EIP) != MAGIC_RET:
            return "invalid", "unicorn budget"

        rc = self.lib.rt_run(self.index[entry], ctypes.addressof(self.cpu), BUDGET)
        if rc:
            return "fail", f"native trap {rc} @0x{self.lib.rt_trap_addr():x}"

        diffs = []
        for g in GPRS:
            a, b = self.getreg(g), mu.reg_read(UC_GPR[g])
            if a != b:
                diffs.append(f"{g} native={a:#x} x86={b:#x}")
        fl = mu.reg_read(UC_X86_REG_EFLAGS)
        flag_diffs = [f for f in CMP_FLAGS if self.getreg(f, 1) != (fl >> FLAGS[f]) & 1]
        sw = mu.reg_read(UC_X86_REG_FPSW)
        top = (sw >> 11) & 7
        if top != 0:
            mant, exp = mu.reg_read(UC_X86_REG_FP0 + top)
            off, _ = self.R["ST0"]
            a = struct.unpack("<d", bytes(self.cpu[off:off + 8]))[0]     # x87 registers are doubles
            b = f80_to_float(mant, exp)
            if not feq(a, b):
                diffs.append(f"ST0 native={a!r} x86={b!r}")
        for i in range(8):
            a = self.getreg(f"XMM{i}", 16)
            b = mu.reg_read(UC_X86_REG_XMM0 + i)
            if a != b:
                fa = struct.unpack("<4f", a.to_bytes(16, "little"))
                fb = struct.unpack("<4f", b.to_bytes(16, "little"))
                kind = "nan-payload" if all(feq(x, y) for x, y in zip(fa, fb)) else "value"
                diffs.append(f"XMM{i} {kind}")
        for base, size in self.regions:
            a = ctypes.string_at(self.mem + base, size)
            b = bytes(mu.mem_read(base, size))
            if a != b:
                k = next(i for i in range(size) if a[i] != b[i])
                diffs.append(f"mem@{base + k:#x} native={a[k]:#04x} x86={b[k]:#04x}")
        if diffs:
            return "fail", "; ".join(diffs[:4])
        if flag_diffs:
            return "flags", ",".join(flag_diffs)
        return "pass", ""


def judge(entry, res):
    valid = [r for r in res if r[0] != "invalid"]
    if not valid:
        verdict = "untestable"
    elif any(r[0] == "fail" for r in valid):
        verdict = "fail"
    elif any(r[0] == "flags" for r in valid):
        verdict = "flags-only"
    else:
        verdict = "pass"
    detail = next((r[1] for r in valid if r[0] in ("fail", "flags")), res[0][1] if not valid else "")
    return {"entry": entry, "verdict": verdict, "valid": len(valid), "detail": detail}


def worker_main(args):
    """Reads one hex entry per stdin line, answers one JSON line. Native crashes kill this process;
    the parent attributes the crash to the entry it was working on and starts a fresh worker."""
    w = Worker(args.exe, args.lib, json.load(open(args.regs)))
    for line in sys.stdin:
        entry = int(line, 16)
        rng = random.Random(args.seed ^ entry)
        print(json.dumps(judge(entry, [w.trial(entry, rng) for _ in range(args.trials)])), flush=True)


def run_pool(args, entries):
    todo = list(reversed(entries))
    lock = threading.Lock()
    results = []
    cmd = [sys.executable, "-I", __file__, args.exe, args.lib, args.regs, "-", "--worker",
           "--trials", str(args.trials), "--seed", str(args.seed)]

    def spawn():
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def thread():
        proc = spawn()
        while True:
            with lock:
                if not todo:
                    break
                entry = todo.pop()
            proc.stdin.write(f"{entry:x}\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if line:
                r = json.loads(line)
            else:
                rc = proc.wait()
                r = {"entry": entry, "verdict": "crash", "valid": 0, "detail": f"worker died rc={rc}"}
                proc = spawn()
            with lock:
                results.append(r)
                if len(results) % 1000 == 0:
                    print(f"{len(results)}/{len(entries)} {dict(Counter(x['verdict'] for x in results))}",
                          file=sys.stderr, flush=True)
        proc.stdin.close()
        proc.wait()

    ts = [threading.Thread(target=thread) for _ in range(args.jobs)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("lib")
    ap.add_argument("regs")
    ap.add_argument("out")
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--jobs", type=int, default=14)
    ap.add_argument("--only", default="")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--worker", action="store_true")
    args = ap.parse_args()
    if args.worker:
        return worker_main(args)

    probe = ctypes.CDLL(args.lib)
    probe.rt_addr.restype = ctypes.c_uint32
    entries = [probe.rt_addr(i) for i in range(probe.rt_count())]
    if args.only:
        want = {int(x, 16) for x in args.only.split(",")}
        entries = [e for e in entries if e in want]

    results = run_pool(args, entries)
    results.sort(key=lambda r: r["entry"])
    summary = Counter(r["verdict"] for r in results)
    json.dump({"summary": summary, "results": results}, open(args.out, "w"), indent=0)
    print(dict(summary))


if __name__ == "__main__":
    main()
