#!/usr/bin/env python3
"""P-code JSONL (scripts/DumpPcode.java) -> C translation units over tools/recomp/rt.h.

    emit.py <in.jsonl> <outdir> [--per-tu 400]

Writes outdir/tu_NNN.c, outdir/table.c (guest address -> host function) and
outdir/emit_report.json (which functions were skipped and why).
"""
import argparse
import json
import os
import sys
from collections import Counter

RAM_SPACE_IDS = None  # LOAD/STORE input0 is a space id constant; we only have one data space


# x87 TOP deltas by mnemonic (push = -1, pop = +1); Ghidra's model does not track TOP itself.
X87_PUSH = {"FLD", "FILD", "FBLD", "FLD1", "FLDZ", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2",
            "FPTAN", "FXTRACT", "FSINCOS"}
X87_POP = {"FSTP", "FISTP", "FISTTP", "FBSTP", "FADDP", "FSUBP", "FSUBRP", "FMULP", "FDIVP", "FDIVRP",
           "FCOMP", "FUCOMP", "FCOMIP", "FUCOMIP", "FICOMP", "FPATAN", "FYL2X", "FYL2XP1"}
X87_POP2 = {"FCOMPP", "FUCOMPP"}
X87_RESET = {"FINIT", "FNINIT"}
FPUSW = 4258


def top_delta(mnemonic):
    m = mnemonic.split()[0].upper()
    if m in X87_PUSH:
        return -1
    if m in X87_POP:
        return 1
    if m in X87_POP2:
        return 2
    return 0


class Unsupported(Exception):
    pass


def hx(v):
    return format(v, "x")


class FnEmitter:
    entries = set()     # every guest function entry being emitted (filled by main)
    extras = {}         # function entry -> [secondary entry addresses] (FixEntries.java)
    userops = []        # CALLOTHER index -> name (from <in>.userops.json)

    def __init__(self, fn):
        self.fn = fn
        self.refs = set()
        self.lines = []
        self.addrs = {i["a"] for i in fn["insns"]}
        self.umap, self.usize = self.layout_uniques(fn)

    @staticmethod
    def layout_uniques(fn):
        """Ghidra's unique space is byte-addressed: a 16-byte temp is often read back as 4-byte
        slices at +4/+8/+12. Merge overlapping [off, off+size) intervals and pack them into one
        local byte buffer, keeping relative offsets inside each merged interval."""
        iv = set()
        for insn in fn["insns"]:
            for opc, out, ins in insn["ops"]:
                for v in ([out] if out else []) + ins:
                    if v and v[0] == "unique":
                        iv.add((v[1], v[1] + v[2]))
        umap, base, cur = {}, 0, None
        for lo, hi in sorted(iv):
            if cur is None or lo >= cur[1]:
                if cur:
                    base += (cur[1] - cur[0] + 7) & ~7
                cur = [lo, hi]
            else:
                cur[1] = max(cur[1], hi)
            umap[lo] = (cur[0], base)
        size = base + (((cur[1] - cur[0] + 7) & ~7) if cur else 0)
        return umap, max(size, 8)

    def uoff(self, off):
        start, base = self.umap[off]
        return base + (off - start)

    # ---- varnodes ------------------------------------------------------------------------
    def rd(self, v):
        sp, off, n = v
        if sp == "const":
            return f"((U)0x{hx(off & ((1 << (8 * min(n, 8))) - 1))}ULL)"
        if sp == "register":
            return f"LD(R+{off},{n})"
        if sp == "unique":
            return f"LD(UQ+{self.uoff(off)},{n})"
        if sp == "ram":
            return f"LD(MEM+0x{hx(off)}u,{n})"
        raise Unsupported(f"space {sp}")

    def wr(self, v, expr):
        sp, off, n = v
        if sp == "register":
            return f"ST(R+{off},{expr},{n});"
        if sp == "unique":
            return f"ST(UQ+{self.uoff(off)},{expr},{n});"
        if sp == "ram":
            return f"ST(MEM+0x{hx(off)}u,{expr},{n});"
        raise Unsupported(f"write space {sp}")

    # ---- one op --------------------------------------------------------------------------
    def op(self, insn, idx, o):
        opc, out, ins = o
        a = insn["a"]
        r = self.rd
        n = out[2] if out else 0
        n0 = ins[0][2] if ins else 0
        b2 = {"INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*", "INT_AND": "&", "INT_OR": "|",
              "INT_XOR": "^", "BOOL_AND": "&", "BOOL_OR": "|", "BOOL_XOR": "^"}
        cmpu = {"INT_EQUAL": "==", "INT_NOTEQUAL": "!=", "INT_LESS": "<", "INT_LESSEQUAL": "<="}
        cmps = {"INT_SLESS": "<", "INT_SLESSEQUAL": "<="}
        fb = {"FLOAT_ADD": "+", "FLOAT_SUB": "-", "FLOAT_MULT": "*", "FLOAT_DIV": "/"}
        fc = {"FLOAT_EQUAL": "==", "FLOAT_NOTEQUAL": "!=", "FLOAT_LESS": "<", "FLOAT_LESSEQUAL": "<="}

        if opc == "COPY":
            return self.wr(out, r(ins[0]))
        if opc == "LOAD":
            return self.wr(out, f"LD(GM({r(ins[1])}),{n})")
        if opc == "STORE":
            return f"ST(GM({r(ins[1])}),{r(ins[2])},{ins[2][2]});"
        if opc in b2:
            return self.wr(out, f"({r(ins[0])}{b2[opc]}{r(ins[1])})")
        if opc in cmpu:
            return self.wr(out, f"(U)({r(ins[0])}{cmpu[opc]}{r(ins[1])})")
        if opc in cmps:
            return self.wr(out, f"(U)(SX({r(ins[0])},{n0}){cmps[opc]}SX({r(ins[1])},{n0}))")
        if opc == "INT_NEGATE":
            return self.wr(out, f"(~{r(ins[0])})")
        if opc == "INT_2COMP":
            return self.wr(out, f"(-{r(ins[0])})")
        if opc == "BOOL_NEGATE":
            return self.wr(out, f"({r(ins[0])}^1)")
        if opc == "INT_ZEXT":
            return self.wr(out, r(ins[0]))
        if opc == "INT_SEXT":
            return self.wr(out, f"(U)SX({r(ins[0])},{n0})")
        if opc == "INT_LEFT":
            return self.wr(out, f"SHL({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_RIGHT":
            return self.wr(out, f"SHR({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_SRIGHT":
            return self.wr(out, f"SAR({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_CARRY":
            return self.wr(out, f"(U)((({r(ins[0])}+{r(ins[1])})&MASK({n0}))<{r(ins[0])})")
        if opc == "INT_SCARRY":
            return self.wr(out, f"SCARRY({r(ins[0])},{r(ins[1])},{n0})")
        if opc == "INT_SBORROW":
            return self.wr(out, f"SBORROW({r(ins[0])},{r(ins[1])},{n0})")
        if opc in ("INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"):
            d = r(ins[1])
            guard = f"if(({d})==0)rt_trap(c,TRAP_DIV0,0x{hx(a)}u);"
            if opc == "INT_DIV":
                e = f"({r(ins[0])}/{d})"
            elif opc == "INT_REM":
                e = f"({r(ins[0])}%{d})"
            elif opc == "INT_SDIV":
                e = f"(U)(SX({r(ins[0])},{n0})/SX({d},{n0}))"
            else:
                e = f"(U)(SX({r(ins[0])},{n0})%SX({d},{n0}))"
            return guard + self.wr(out, e)
        if opc == "POPCOUNT":
            return self.wr(out, f"POPC({r(ins[0])})")
        if opc == "SUBPIECE":
            return self.wr(out, f"({r(ins[0])}>>{8 * ins[1][1]})")
        if opc == "PIECE":
            return self.wr(out, f"(({r(ins[0])}<<{8 * ins[1][2]})|{r(ins[1])})")
        if opc in fb:
            return self.wr(out, f"FBIN({fb[opc]},{r(ins[0])},{n0},{r(ins[1])},{ins[1][2]},{n})")
        if opc in fc:
            return self.wr(out, f"(U)(FG({r(ins[0])},{n0}){fc[opc]}FG({r(ins[1])},{ins[1][2]}))")
        if opc == "FLOAT_NAN":
            return self.wr(out, f"(U)isnan(FG({r(ins[0])},{n0}))")
        if opc == "FLOAT_NEG":
            return self.wr(out, f"FP(-FG({r(ins[0])},{n0}),{n})")
        if opc == "FLOAT_ABS":
            return self.wr(out, f"FP(fabs(FG({r(ins[0])},{n0})),{n})")
        if opc == "FLOAT_SQRT":
            return self.wr(out, f"FP(isnan(FG({r(ins[0])},{n0}))?FG({r(ins[0])},{n0}):XNAN(sqrt(FG({r(ins[0])},{n0}))),{n})")
        if opc == "INT2FLOAT":
            return self.wr(out, f"FP((double)SX({r(ins[0])},{n0}),{n})")
        if opc == "FLOAT2FLOAT":
            return self.wr(out, f"FP(FG({r(ins[0])},{n0}),{n})")
        if opc == "TRUNC":
            return self.wr(out, f"FTRUNC(trunc(FG({r(ins[0])},{n0})),{n})")
        if opc == "ROUND":
            return self.wr(out, f"FP(nearbyint(FG({r(ins[0])},{n0})),{n})")
        if opc == "FLOAT_CEIL":
            return self.wr(out, f"FP(ceil(FG({r(ins[0])},{n0})),{n})")
        if opc == "FLOAT_FLOOR":
            return self.wr(out, f"FP(floor(FG({r(ins[0])},{n0})),{n})")
        if opc in ("BRANCH", "CBRANCH"):
            tgt = ins[0]
            if tgt[0] == "const":
                rel = tgt[1] if tgt[1] < (1 << 63) else tgt[1] - (1 << 64)
                lab = self.plabel(a, idx + rel, len(insn["ops"]))
            else:
                if tgt[1] not in self.addrs:
                    # jump into another function: a tail call
                    tail = f"{{{self.call(tgt[1])}return;}}"
                    return tail if opc == "BRANCH" else f"if({r(ins[1])}&1){tail}"
                lab = f"L_{hx(tgt[1])}"
            g = f"{{if(--rt_budget<0)rt_trap(c,TRAP_BUDGET,0x{hx(a)}u);goto {lab};}}"
            return g if opc == "BRANCH" else f"if({r(ins[1])}&1){g}"
        if opc == "BRANCHIND":
            cases = "".join(f"case 0x{hx(t)}u:goto L_{hx(t)};" for t in insn.get("targets", [])
                            if t in self.addrs)
            return (f"if(--rt_budget<0)rt_trap(c,TRAP_BUDGET,0x{hx(a)}u);"
                    f"switch((uint32_t){r(ins[0])}){{{cases}default:rt_call(c,(uint32_t){r(ins[0])});return;}}")
        if opc == "RETURN":
            return "return;"
        if opc == "CALL":
            return self.call(ins[0][1])
        if opc == "CALLIND":
            return f"rt_call(c,(uint32_t){r(ins[0])});"
        if opc == "CALLOTHER":
            return self.callother(insn, out, ins)
        raise Unsupported(f"op {opc}")

    def call(self, target):
        if target in self.entries:
            self.refs.add(target)
            return f"g_{hx(target)}(c);"
        return f"rt_call(c,0x{hx(target)}u);"

    def callother(self, insn, out, ins):
        name = self.userops[ins[0][1]]
        r = self.rd
        a = [r(v) for v in ins[1:]]
        n = out[2] if out else 0
        simple = {
            "rdtsc": "(U)rt_rdtsc()",
            "movmskps": f"MOVMSKPS({a[-1]})" if a else None,
            "minps": f"MINPS({a[0]},{a[1]})" if len(a) > 1 else None,
            "maxps": f"MAXPS({a[0]},{a[1]})" if len(a) > 1 else None,
            "divps": f"DIVPS({a[0]},{a[1]})" if len(a) > 1 else None,
            "rsqrtps": f"RSQRTPS({a[-1]})" if a else None,
            "rcpps": f"RCPPS({a[-1]})" if a else None,
            "rsqrtss": f"RSQRTSS({a[0]},{a[-1]})" if a else None,
            "paddusw": f"PADDUSW({a[0]},{a[1]})" if len(a) > 1 else None,
            "fsin": f"FP(sin(FG({a[0]},10)),{n})" if a else None,
            "fcos": f"FP(cos(FG({a[0]},10)),{n})" if a else None,
            "fptan": f"FP(tan(FG({a[0]},10)),{n})" if a else None,
            "fpatan": f"FP(atan2(FG({a[0]},10),FG({a[1]},10)),{n})" if len(a) > 1 else None,
            "fscale": f"FP(ldexp(FG({a[0]},10),(int)trunc(FG({a[1]},10))),{n})" if len(a) > 1 else None,
            "log2": f"FP(log2(FG({a[0]},10)),{n})" if a else None,
            "f2xm1": f"FP(expm1(FG({a[0]},10)*M_LN2),{n})" if a else None,
        }
        if name in ("LOCK", "UNLOCK"):
            # single-threaded semantics for now; threads need real atomics (M2)
            return "/* lock */"
        e = simple.get(name)
        if e is None or out is None:
            raise Unsupported(f"callother {name}")
        return self.wr(out, e)

    def plabel(self, a, k, nops):
        self.ptargets.add(k)
        return f"P_{hx(a)}_{k}"

    # ---- whole function ------------------------------------------------------------------
    def emit(self):
        fn = self.fn
        insns = sorted(fn["insns"], key=lambda i: i["a"])
        if any("GS:" in i["m"] for i in insns):
            raise Unsupported("GS segment")
        body = []
        if insns and insns[0]["a"] != fn["entry"]:
            # body has code at addresses below the entry (shared exit blocks in hand-written CRT
            # code): start at the real entry, not at the lowest address
            if fn["entry"] not in self.addrs:
                raise Unsupported("entry not in body")
            body.append(f"  goto L_{hx(fn['entry'])};")
        for k, insn in enumerate(insns):
            a = insn["a"]
            self.ptargets = set()
            mn = insn["m"].split()[0].upper()
            if mn == "CPUID":
                opl, insn = ["rt_cpuid(c);"], dict(insn, ops=[["COPY", None, []]])
            elif mn in ("FPREM", "FPREM1"):
                # Ghidra's model computes the remainder but never touches C2, so the CRT's
                # `fprem; fstsw ax; sahf; jp again` loop exits on a stale flag. Do the complete
                # reduction in one step (exact in double) and report it complete (C2 = 0).
                fn_ = "fmod" if mn == "FPREM" else "remainder"
                opl = [f"ST(R+4352,FP({fn_}(FG(LD(R+4352,10),10),FG(LD(R+4368,10),10)),10),10);"
                       "R[4242]=0;ST(R+4258,LD(R+4258,2)&~(U)0x400,2);"]
                insn = dict(insn, ops=[["COPY", None, []]])
            elif mn == "INT3":
                opl, insn = [f"rt_trap(c,TRAP_INT3,0x{hx(a)}u);"], dict(insn, ops=[["RETURN", None, []]])
            else:
                opl = [self.op(insn, j, o) for j, o in enumerate(insn["ops"])]
            body.append(f"L_{hx(a)}: /* {insn['m']} */")
            if any(v and v[0] == "register" and v[1] <= FPUSW < v[1] + v[2]
                   for o in insn["ops"] for v in o[2]):
                body.append("  SYNC_FPUSW(R);")
            if insn["m"].split()[0].upper() in X87_RESET:
                body.append("  R[REG_TOP]=0;")
            d = top_delta(insn["m"])
            if d:
                # applied before the ops: no x87 instruction branches, so it always executes
                body.append(f"  TOPADJ(R,{d});")
            for j, s in enumerate(opl):
                if j in self.ptargets:
                    body.append(f"P_{hx(a)}_{j}:;")
                body.append("  " + s)
            if len(insn["ops"]) in self.ptargets:
                body.append(f"P_{hx(a)}_{len(insn['ops'])}:;")
            last = insn["ops"][-1][0] if insn["ops"] else None
            nxt = a + insn["len"]
            following = insns[k + 1]["a"] if k + 1 < len(insns) else None
            if last in ("BRANCH", "RETURN", "BRANCHIND"):
                continue
            if following != nxt:
                if nxt in self.addrs:
                    body.append(f"  goto L_{hx(nxt)};")
                else:
                    # falls off the end into code Ghidra gave to another function
                    body.append(f"  {self.call(nxt)}return;")
        decl = f"uint8_t UQ[{self.usize}]={{0}};"
        e0 = fn["entry"]
        name = f"g_{hx(e0)}"
        extra = [x for x in self.extras.get(e0, []) if x in self.addrs and x != e0]
        self.extra_emitted = extra
        # keep every referenced entry (own entries included) in refs: a body can call its own
        # secondary entry, whose wrapper is defined after it, so it needs the forward declaration
        if not extra:
            return name, (f"/* {fn['name']} */\nvoid {name}(CPU *c){{uint8_t *R=c->r;{decl}RT_ENTER(0x{hx(e0)}u);\n"
                          + "\n".join(body) + "\n}\n")
        # several entry points share one body (hand-written code with secondary entries)
        sw = "".join(f"case {k + 1}:goto L_{hx(x)};" for k, x in enumerate(extra))
        out = (f"/* {fn['name']} (+{len(extra)} entries) */\nstatic void b_{hx(e0)}(CPU *c,int ent){{"
               f"uint8_t *R=c->r;{decl}switch(ent){{{sw}default:break;}}\n" + "\n".join(body) + "\n}\n")
        out += f"void {name}(CPU *c){{RT_ENTER(0x{hx(e0)}u);b_{hx(e0)}(c,0);}}\n"
        out += "".join(f"void g_{hx(x)}(CPU *c){{RT_ENTER(0x{hx(x)}u);b_{hx(e0)}(c,{k + 1});}}\n" for k, x in enumerate(extra))
        return name, out


def write_if_changed(path, text):
    """Keep mtimes stable for unchanged translation units so build.sh can skip them."""
    if os.path.exists(path):
        with open(path) as f:
            if f.read() == text:
                return
    with open(path, "w") as f:
        f.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inp")
    ap.add_argument("outdir")
    ap.add_argument("--per-tu", type=int, default=400)
    ap.add_argument("--extra", help="extra_entries.json from FixEntries.java")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    up = args.inp + ".userops.json"
    if os.path.exists(up):
        FnEmitter.userops = json.load(open(up))
    FnEmitter.entries = {json.loads(l)["entry"] for l in open(args.inp)}
    if args.extra:
        FnEmitter.extras = {int(k): v for k, v in json.load(open(args.extra)).items()}
    # Pass 1: a jump that leaves its function and lands *inside* another one (e.g. the code after
    # an SEH __except block, which analysis split off) makes that address an extra entry.
    owner = {}
    out_jumps = []
    for line in open(args.inp):
        fn = json.loads(line)
        mine = {i["a"] for i in fn["insns"]}
        for i in fn["insns"]:
            owner[i["a"]] = fn["entry"]
            for opc, _, ins in i["ops"]:
                if opc in ("BRANCH", "CBRANCH") and ins[0][0] == "ram" and ins[0][1] not in mine:
                    out_jumps.append(ins[0][1])
    added = 0
    for t in out_jumps:
        f = owner.get(t)
        if f is not None and t != f and t not in FnEmitter.extras.get(f, []):
            FnEmitter.extras.setdefault(f, []).append(t)
            added += 1
    del owner
    print(f"pass 1: {len(out_jumps)} cross-function jumps, {added} new extra entries", file=sys.stderr)
    for v in FnEmitter.extras.values():
        v.sort()
        FnEmitter.entries.update(v)

    ok, skipped, why = [], [], Counter()
    tu, tu_idx, chunk = [], 0, []
    chunk_key = None
    refs = set()

    def flush():
        nonlocal tu_idx, chunk, refs
        if not chunk:
            return
        text = ('#include "rt.h"\n#pragma clang diagnostic ignored "-Wunused-label"\n'
                + "".join(f"void g_{hx(t)}(CPU *);\n" for t in sorted(refs)) + "\n".join(chunk))
        write_if_changed(os.path.join(args.outdir, f"tu_{chunk_key:05x}.c"), text)
        tu_idx += 1
        chunk, refs = [], set()

    for line in open(args.inp):
        fn = json.loads(line)
        try:
            em = FnEmitter(fn)
            name, code = em.emit()
        except Unsupported as e:
            reason = str(e)
            why[reason] += 1
            skipped.append({"entry": fn["entry"], "reason": reason})
            continue
        # translation units are keyed by address range, not by count: a newly discovered function
        # then changes one TU instead of shifting every later boundary (incremental rebuilds)
        key = fn["entry"] >> 15
        if chunk and key != chunk_key:
            flush()
        chunk_key = key
        ok.append((fn["entry"], name))
        ok.extend((x, f"g_{hx(x)}") for x in em.extra_emitted)
        refs |= em.refs
        chunk.append(code)
    flush()

    # a skipped function referenced directly would be an undefined symbol: give it a trap stub
    emitted = {e for e, _ in ok}
    stubs = ['#include "rt.h"\n']
    if True:
        # anything declared callable but not emitted (skipped, or an extra entry that was not an
        # instruction start in its function) traps instead of failing to link
        for e in sorted(FnEmitter.entries - emitted):
            stubs.append(f"void g_{hx(e)}(CPU *c){{rt_trap(c,TRAP_UNSUPPORTED,0x{hx(e)}u);}}\n")
    write_if_changed(os.path.join(args.outdir, "stubs.c"), "".join(stubs))
    ok.sort()
    write_if_changed(os.path.join(args.outdir, "table.c"),
                     '#include "rt.h"\n' + "".join(f"void {name}(CPU *);\n" for _, name in ok)
                     + "const uint32_t rt_fn_addr[] = {" + ",".join(f"0x{hx(e)}u" for e, _ in ok) + "};\n"
                     + "const GuestFn rt_fn_ptr[] = {" + ",".join(n for _, n in ok) + "};\n"
                     + f"const int rt_fn_count = {len(ok)};\n")
    with open(os.path.join(args.outdir, "emit_report.json"), "w") as f:
        json.dump({"emitted": len(ok), "skipped": len(skipped), "reasons": why.most_common(),
                   "skipped_fns": skipped}, f, indent=1)
    print(f"emitted {len(ok)}, skipped {len(skipped)}: {why.most_common(8)}", file=sys.stderr)


if __name__ == "__main__":
    main()
