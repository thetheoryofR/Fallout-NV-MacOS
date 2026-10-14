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


# x86 registers kept in C locals (fast path): the 8 GPRs (offsets 0..31) and the flag bytes.
GPR_NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
FLAG_OFFS = {512: "fCF", 514: "fPF", 516: "fAF", 518: "fZF", 519: "fSF", 522: "fDF", 523: "fOF"}


class FnEmitter:
    entries = set()     # every guest function entry being emitted (filled by main)
    extras = {}         # function entry -> [secondary entry addresses] (FixEntries.java)
    userops = []        # CALLOTHER index -> name (from <in>.userops.json)

    def __init__(self, fn):
        self.fn = fn
        self.refs = set()
        self.addrs = {i["a"] for i in fn["insns"]}
        self.ulocal, self.umap, self.usize = self.layout_uniques(fn)
        self.gw, self.gr = set(), set()          # cached registers written / read

    @staticmethod
    def layout_uniques(fn):
        """Ghidra's unique space is byte-addressed. Temps accessed only at one (offset, size) become
        scalar locals; overlapping ones share a byte buffer with relative offsets preserved."""
        acc = {}
        for insn in fn["insns"]:
            for opc, out, ins in insn["ops"]:
                for v in ([out] if out else []) + ins:
                    if v and v[0] == "unique":
                        acc.setdefault(v[1], set()).add(v[2])
        iv = sorted((o, o + max(s)) for o, s in acc.items())
        groups, cur = [], None
        for lo, hi in iv:
            if cur is None or lo >= cur[1]:
                if cur:
                    groups.append(cur)
                cur = [lo, hi, [lo]]
            else:
                cur[1] = max(cur[1], hi)
                cur[2].append(lo)
        if cur:
            groups.append(cur)
        ulocal, umap, base = {}, {}, 0
        for lo, hi, offs in groups:
            if len(offs) == 1 and len(acc[lo]) == 1:
                ulocal[lo] = (f"t{lo:x}", next(iter(acc[lo])))
            else:
                for o in offs:
                    umap[o] = (lo, base)
                base += (hi - lo + 7) & ~7
        return ulocal, umap, max(base, 8)

    def uoff(self, off):
        start, base = self.umap[off]
        return base + (off - start)

    # ---- varnodes: narrow (<= 8 bytes) values are V (uint64_t), wide ones U (__int128) ----------
    def cached(self, off, n):
        if off < 32:
            if (off & 3) + n > 4:
                raise Unsupported("register access spans GPRs")
            return "g"
        if off in FLAG_OFFS and n == 1:
            return "f"
        if off < 1024 and n <= 4 and any(o <= off < o + 1 for o in FLAG_OFFS):
            raise Unsupported("flag access not byte-sized")
        return None

    def rd(self, v):
        sp, off, n = v
        wide = n > 8
        if sp == "const":
            return (f"((U)0x{hx(off)}ULL)" if wide else f"((V)0x{hx(off & ((1 << (8 * min(n, 8))) - 1))}ULL)")
        if sp == "register":
            k = self.cached(off, n)
            if k == "g":
                g = GPR_NAMES[off >> 2]
                self.gr.add(g)
                sh = 8 * (off & 3)
                if n == 4:
                    return f"((V){g})"
                return f"((V)(({g}>>{sh})&0x{(1 << (8 * n)) - 1:x}u))"
            if k == "f":
                self.gr.add(FLAG_OFFS[off])
                return f"((V){FLAG_OFFS[off]})"
            return f"LD(R+{off},{n})" if wide else f"LDV(R+{off},{n})"
        if sp == "unique":
            if off in self.ulocal:
                return self.ulocal[off][0]
            return f"LD(UQ+{self.uoff(off)},{n})" if wide else f"LDV(UQ+{self.uoff(off)},{n})"
        if sp == "ram":
            return f"LDMW(0x{hx(off)}u,{n})" if wide else f"LDM(0x{hx(off)}u,{n})"
        raise Unsupported(f"space {sp}")

    def rdU(self, v):
        e = self.rd(v)
        return e if v[2] > 8 or v[0] == "const" and v[2] > 8 else f"((U){e})"

    def wr(self, v, expr):
        sp, off, n = v
        wide = n > 8
        e = expr if wide else f"((V)({expr}))"
        if sp == "register":
            k = self.cached(off, n)
            if k == "g":
                g = GPR_NAMES[off >> 2]
                self.gw.add(g)
                if n == 4:
                    return f"{g}=(uint32_t){e};"
                self.gr.add(g)
                sh, m = 8 * (off & 3), (1 << (8 * n)) - 1
                return f"{g}=({g}&~(0x{m:x}u<<{sh}))|(((uint32_t){e}&0x{m:x}u)<<{sh});"
            if k == "f":
                self.gw.add(FLAG_OFFS[off])
                return f"{FLAG_OFFS[off]}=(uint8_t){e};"
            return f"ST(R+{off},{e},{n});" if wide else f"STV(R+{off},{e},{n});"
        if sp == "unique":
            if off in self.ulocal:
                return f"{self.ulocal[off][0]}=({e})&{'MASK' if wide else 'MASKV'}({n});"
            return f"ST(UQ+{self.uoff(off)},{e},{n});" if wide else f"STV(UQ+{self.uoff(off)},{e},{n});"
        if sp == "ram":
            return f"STMW(0x{hx(off)}u,{e},{n});" if wide else f"STM(0x{hx(off)}u,{e},{n});"
        raise Unsupported(f"write space {sp}")

    # register spill / reload around anything that can observe c->r
    def save(self):
        return "SAVE_REGS;" if any(g in self.gw for g in GPR_NAMES) else ""

    def load_stmt(self):
        return "LOAD_REGS;"

    # ---- one op --------------------------------------------------------------------------------
    def op(self, insn, idx, o):
        opc, out, ins = o
        a = insn["a"]
        n = out[2] if out else 0
        n0 = ins[0][2] if ins else 0
        sizes = [v[2] for v in ([out] if out else []) + ins if v and v[0] != "const"]
        wide = any(s > 8 for s in sizes) or (opc == "SUBPIECE" and n0 > 8)
        r = self.rdU if wide else self.rd
        M = "MASK" if wide else "MASKV"
        X = "" if wide else "V"           # macro suffix
        T = "U" if wide else "V"
        S = "SX" if wide else "SXV"
        b2 = {"INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*", "INT_AND": "&", "INT_OR": "|",
              "INT_XOR": "^", "BOOL_AND": "&", "BOOL_OR": "|", "BOOL_XOR": "^"}
        cmpu = {"INT_EQUAL": "==", "INT_NOTEQUAL": "!=", "INT_LESS": "<", "INT_LESSEQUAL": "<="}
        cmps = {"INT_SLESS": "<", "INT_SLESSEQUAL": "<="}
        fb = {"FLOAT_ADD": "+", "FLOAT_SUB": "-", "FLOAT_MULT": "*", "FLOAT_DIV": "/"}
        fc = {"FLOAT_EQUAL": "==", "FLOAT_NOTEQUAL": "!=", "FLOAT_LESS": "<", "FLOAT_LESSEQUAL": "<="}
        FG = (lambda e, k: f"FG({e},{k})") if wide else (lambda e, k: f"FGV({e},{k})")
        # a float read of a varnode: its own width decides FG vs FGV
        def fg(v):
            return f"FG({self.rdU(v)},{v[2]})" if v[2] > 8 else f"FGV({self.rd(v)},{v[2]})"
        def fp(e):
            return f"FP({e},{n})" if n > 8 else f"FPV({e},{n})"

        if opc == "COPY":
            return self.wr(out, self.rdU(ins[0]) if n > 8 else self.rd(ins[0]))
        if opc == "LOAD":
            addr = self.rd(ins[1]) if ins[1][2] <= 8 else self.rdU(ins[1])
            return self.wr(out, f"LDMW((uint32_t)({addr}),{n})" if n > 8 else f"LDM((uint32_t)({addr}),{n})")
        if opc == "STORE":
            addr = self.rd(ins[1]) if ins[1][2] <= 8 else self.rdU(ins[1])
            val = self.rdU(ins[2]) if ins[2][2] > 8 else self.rd(ins[2])
            return (f"STMW((uint32_t)({addr}),{val},{ins[2][2]});" if ins[2][2] > 8 else f"STM((uint32_t)({addr}),{val},{ins[2][2]});")
        if opc in b2:
            return self.wr(out, f"({r(ins[0])}{b2[opc]}{r(ins[1])})")
        if opc in cmpu:
            return self.wr(out, f"({T})({r(ins[0])}{cmpu[opc]}{r(ins[1])})")
        if opc in cmps:
            return self.wr(out, f"({T})({S}({r(ins[0])},{n0}){cmps[opc]}{S}({r(ins[1])},{n0}))")
        if opc == "INT_NEGATE":
            return self.wr(out, f"(~{r(ins[0])})")
        if opc == "INT_2COMP":
            return self.wr(out, f"(-{r(ins[0])})")
        if opc == "BOOL_NEGATE":
            return self.wr(out, f"({r(ins[0])}^1)")
        if opc == "INT_ZEXT":
            return self.wr(out, r(ins[0]))
        if opc == "INT_SEXT":
            return self.wr(out, f"({T}){S}({r(ins[0])},{n0})")
        if opc == "INT_LEFT":
            return self.wr(out, f"SHL{X}({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_RIGHT":
            return self.wr(out, f"SHR{X}({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_SRIGHT":
            return self.wr(out, f"SAR{X}({r(ins[0])},{r(ins[1])},{n})")
        if opc == "INT_CARRY":
            return self.wr(out, f"({T})((({r(ins[0])}+{r(ins[1])})&{M}({n0}))<{r(ins[0])})")
        if opc == "INT_SCARRY":
            return self.wr(out, f"SCARRY{X}({r(ins[0])},{r(ins[1])},{n0})")
        if opc == "INT_SBORROW":
            return self.wr(out, f"SBORROW{X}({r(ins[0])},{r(ins[1])},{n0})")
        if opc in ("INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"):
            d = r(ins[1])
            guard = f"if(({d})==0){{{self.save()}rt_trap(c,TRAP_DIV0,0x{hx(a)}u);}}"
            if opc == "INT_DIV":
                e = f"({r(ins[0])}/{d})"
            elif opc == "INT_REM":
                e = f"({r(ins[0])}%{d})"
            elif opc == "INT_SDIV":
                e = f"({T})({S}({r(ins[0])},{n0})/{S}({d},{n0}))"
            else:
                e = f"({T})({S}({r(ins[0])},{n0})%{S}({d},{n0}))"
            return guard + self.wr(out, e)
        if opc == "POPCOUNT":
            return self.wr(out, f"POPC({self.rdU(ins[0])})" if wide else f"(V)__builtin_popcountll({r(ins[0])})")
        if opc == "SUBPIECE":
            src = self.rdU(ins[0]) if n0 > 8 else self.rd(ins[0])
            return self.wr(out, f"({src}>>{8 * ins[1][1]})")
        if opc == "PIECE":
            return self.wr(out, f"(({r(ins[0])}<<{8 * ins[1][2]})|{r(ins[1])})")
        if opc in fb:
            if not wide:
                return self.wr(out, f"FBINV({fb[opc]},{r(ins[0])},{n0},{r(ins[1])},{ins[1][2]},{n})")
            return self.wr(out, f"FBIN({fb[opc]},{self.rdU(ins[0])},{n0},{self.rdU(ins[1])},{ins[1][2]},{n})")
        if opc in fc:
            return self.wr(out, f"(V)({fg(ins[0])}{fc[opc]}{fg(ins[1])})")
        if opc == "FLOAT_NAN":
            return self.wr(out, f"(V)isnan({fg(ins[0])})")
        if opc == "FLOAT_NEG":
            return self.wr(out, fp(f"-{fg(ins[0])}"))
        if opc == "FLOAT_ABS":
            return self.wr(out, fp(f"fabs({fg(ins[0])})"))
        if opc == "FLOAT_SQRT":
            x = fg(ins[0])
            return self.wr(out, fp(f"(isnan({x})?{x}:XNAN(sqrt({x})))"))
        if opc == "INT2FLOAT":
            return self.wr(out, fp(f"(double)SXV({self.rd(ins[0])},{n0})" if n0 <= 8 else f"(double)SX({self.rdU(ins[0])},{n0})"))
        if opc == "FLOAT2FLOAT":
            return self.wr(out, fp(fg(ins[0])))
        if opc == "TRUNC":
            return self.wr(out, f"FTRUNC(trunc({fg(ins[0])}),{n})" if n > 8 else f"FTRUNCV(trunc({fg(ins[0])}),{n})")
        if opc == "ROUND":
            return self.wr(out, fp(f"nearbyint({fg(ins[0])})"))
        if opc == "FLOAT_CEIL":
            return self.wr(out, fp(f"ceil({fg(ins[0])})"))
        if opc == "FLOAT_FLOOR":
            return self.wr(out, fp(f"floor({fg(ins[0])})"))
        if opc in ("BRANCH", "CBRANCH"):
            tgt = ins[0]
            cond = self.rd(ins[1]) if opc == "CBRANCH" else None
            if tgt[0] == "const":
                rel = tgt[1] if tgt[1] < (1 << 63) else tgt[1] - (1 << 64)
                lab = self.plabel(a, idx + rel, len(insn["ops"]))
            else:
                if tgt[1] not in self.addrs:
                    tail = f"{{{self.save()}{self.call_raw(tgt[1])}return;}}"
                    return tail if opc == "BRANCH" else f"if({cond}&1){tail}"
                lab = f"L_{hx(tgt[1])}"
            g = f"{{RT_BRANCH(0x{hx(a)}u);goto {lab};}}"
            return g if opc == "BRANCH" else f"if({cond}&1){g}"
        if opc == "BRANCHIND":
            v = self.rd(ins[0])
            cases = "".join(f"case 0x{hx(t)}u:goto L_{hx(t)};" for t in insn.get("targets", []) if t in self.addrs)
            return (f"RT_BRANCH(0x{hx(a)}u);"
                    f"switch((uint32_t){v}){{{cases}default:{self.save()}rt_call(c,(uint32_t){v});return;}}")
        if opc == "RETURN":
            return f"{self.save()}return;"
        if opc == "CALL":
            return f"{self.save()}{self.call_raw(ins[0][1])}{self.load_stmt()}"
        if opc == "CALLIND":
            return f"{{uint32_t _t=(uint32_t){self.rd(ins[0])};{self.save()}rt_call(c,_t);{self.load_stmt()}}}"
        if opc == "CALLOTHER":
            return self.callother(insn, out, ins)
        raise Unsupported(f"op {opc}")

    def call_raw(self, target):
        if target in self.entries:
            self.refs.add(target)
            return f"g_{hx(target)}(c);"
        return f"rt_call(c,0x{hx(target)}u);"

    def callother(self, insn, out, ins):
        name = self.userops[ins[0][1]]
        a = [self.rdU(v) for v in ins[1:]]
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
        if name == "LOCK":                 # x86 LOCK prefix: make the RMW atomic w.r.t. other LOCKed ops
            return "rt_lock();"
        if name == "UNLOCK":
            return "rt_unlock();"
        e = simple.get(name)
        if e is None or out is None:
            raise Unsupported(f"callother {name}")
        return self.wr(out, e)

    def plabel(self, a, k, nops):
        self.ptargets.add(k)
        return f"P_{hx(a)}_{k}"

    # ---- whole function ------------------------------------------------------------------------
    def emit(self):
        fn = self.fn
        insns = sorted(fn["insns"], key=lambda i: i["a"])
        if any("GS:" in i["m"] for i in insns):
            raise Unsupported("GS segment")
        body = []
        if insns and insns[0]["a"] != fn["entry"]:
            if fn["entry"] not in self.addrs:
                raise Unsupported("entry not in body")
            body.append(f"  goto L_{hx(fn['entry'])};")
        for k, insn in enumerate(insns):
            a = insn["a"]
            self.ptargets = set()
            mn = insn["m"].split()[0].upper()
            if mn == "CPUID":
                self.gw.update(["eax", "ebx", "ecx", "edx"]); self.gr.add("eax")
                opl, insn = [f"SAVE_REGS;rt_cpuid(c);LOAD_REGS;"], dict(insn, ops=[["COPY", None, []]])
            elif mn in ("FPREM", "FPREM1"):
                fn_ = "fmod" if mn == "FPREM" else "remainder"
                opl = [f"ST(R+4352,FP({fn_}(FG(LD(R+4352,10),10),FG(LD(R+4368,10),10)),10),10);"
                       "R[4242]=0;ST(R+4258,LD(R+4258,2)&~(U)0x400,2);"]
                insn = dict(insn, ops=[["COPY", None, []]])
            elif mn == "INT3":
                opl, insn = [f"SAVE_REGS;rt_trap(c,TRAP_INT3,0x{hx(a)}u);"], dict(insn, ops=[["RETURN", None, []]])
            else:
                opl = [self.op(insn, j, o) for j, o in enumerate(insn["ops"])]
            body.append(f"L_{hx(a)}: /* {insn['m']} */")
            if any(v and v[0] == "register" and v[1] <= FPUSW < v[1] + v[2] for o in insn["ops"] for v in o[2]):
                body.append("  SYNC_FPUSW(R);")
            if mn in X87_RESET:
                body.append("  R[REG_TOP]=0;")
            d = top_delta(insn["m"])
            if d:
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
                    body.append(f"  {self.save()}{self.call_raw(nxt)}return;")
        # cached-register declarations, loads and the SAVE/LOAD macros for this function
        used = [g for g in GPR_NAMES if g in self.gr or g in self.gw]
        flags = [(o, nm) for o, nm in FLAG_OFFS.items() if nm in self.gr or nm in self.gw]
        load = "".join(f"{g}=(uint32_t)LDV(R+{4 * GPR_NAMES.index(g)},4);" for g in used)
        # Flags are pure locals: compiled x86 code never passes flags across a call or return, so they
        # are neither spilled nor reloaded — which lets the compiler delete every flag computation
        # (PF popcounts, AF, OF...) that nothing in this function reads.
        save = "".join(f"STV(R+{4 * GPR_NAMES.index(g)},{g},4);" for g in GPR_NAMES if g in self.gw)
        decl = "".join(f"uint32_t {g};" for g in used) + "".join(f"uint8_t {nm}=0;" for _, nm in flags)
        decl += "".join(f"{'U' if sz > 8 else 'V'} {nm}=0;" for nm, sz in self.ulocal.values())
        if self.umap:
            decl += f"uint8_t UQ[{self.usize}]={{0}};"
        macros = f"#define SAVE_REGS {{{save}}}\n#define LOAD_REGS {{{load}}}\n"
        undef = "#undef SAVE_REGS\n#undef LOAD_REGS\n"
        e0 = fn["entry"]
        name = f"g_{hx(e0)}"
        extra = [x for x in self.extras.get(e0, []) if x in self.addrs and x != e0]
        self.extra_emitted = extra
        if not extra:
            return name, (f"/* {fn['name']} */\n{macros}void {name}(CPU *c){{uint8_t *R=c->r;{decl}RT_ENTER(0x{hx(e0)}u);LOAD_REGS;\n"
                          + "\n".join(body) + f"\n}}\n{undef}")
        sw = "".join(f"case {k + 1}:goto L_{hx(x)};" for k, x in enumerate(extra))
        out = (f"/* {fn['name']} (+{len(extra)} entries) */\n{macros}static void b_{hx(e0)}(CPU *c,int ent){{"
               f"uint8_t *R=c->r;{decl}LOAD_REGS;switch(ent){{{sw}default:break;}}\n" + "\n".join(body) + f"\n}}\n{undef}")
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
