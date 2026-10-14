"""Whole-program x86 flag liveness for the recompiler.

Compiled C++ never passes flags across calls, but hand-written runtime code can: a helper may read
a flag its caller set (live-in at entry), or a caller may branch on a flag a helper left behind
(live after a call). This finds exactly those cases so the emitter can spill/reload only them:

    consumers[f]  = flag mask live at f's entry              (direct callers spill it before calling f)
    producers[f]  = flag mask some caller reads after calling f (f stores it at each return)
    reload[(f, a)] = flag mask live right after the CALL at address a in f (reloaded after that call)

Flags are bit-masks over FLAG_OFFS. Analysis is per instruction; an instruction's defs are only
counted when it has no intra-instruction branch (x86 shifts by 0 leave flags untouched).
"""
FLAG_BITS = {512: 1, 514: 2, 516: 4, 518: 8, 519: 16, 522: 32, 523: 64}
ALL = 127


def summarize(fn):
    """Per-instruction (use, def, kind, call_target, succs) for one function."""
    insns = sorted(fn["insns"], key=lambda i: i["a"])
    addrs = {i["a"] for i in insns}
    idx = {i["a"]: k for k, i in enumerate(insns)}
    out = []
    for k, i in enumerate(insns):
        use = dfn = 0
        intra = False
        call = None
        kind = "plain"
        for opc, o, ins in i["ops"]:
            for v in ins:
                if v and v[0] == "register" and v[1] in FLAG_BITS and v[2] == 1:
                    b = FLAG_BITS[v[1]]
                    if not dfn & b:
                        use |= b
            if o and o[0] == "register" and o[1] in FLAG_BITS and o[2] == 1:
                dfn |= FLAG_BITS[o[1]]
            if opc in ("BRANCH", "CBRANCH") and ins[0][0] == "const":
                intra = True
            if opc == "CALL":
                kind, call = "call", ins[0][1]
            elif opc == "CALLIND":
                kind = "calli"
            elif opc == "RETURN":
                kind = "ret"
        if intra:
            dfn = 0
        succ = []
        last = i["ops"][-1][0] if i["ops"] else None
        nxt = i["a"] + i["len"]
        for opc, o, ins in i["ops"]:
            if opc in ("BRANCH", "CBRANCH") and ins[0][0] == "ram":
                if ins[0][1] in idx:
                    succ.append(idx[ins[0][1]])
                else:
                    kind = kind if kind != "plain" else "tail"
                    if kind == "tail":
                        call = ins[0][1]
            if opc == "BRANCHIND":
                for t in i.get("targets", []):
                    if t in idx:
                        succ.append(idx[t])
        if last not in ("BRANCH", "RETURN", "BRANCHIND") and nxt in idx:
            succ.append(idx[nxt])
        out.append([use, dfn, kind, call, succ, i["a"]])
    return out


def analyze(funcs):
    """funcs: {entry: summary}. Returns consumers, producers, reload."""
    consumers = {e: 0 for e in funcs}

    def live(e):
        s = funcs[e]
        n = len(s)
        lin = [0] * n
        changed = True
        while changed:
            changed = False
            for k in range(n - 1, -1, -1):
                use, dfn, kind, call, succ, _ = s[k]
                lo = 0
                for j in succ:
                    lo |= lin[j]
                if kind == "call":
                    # the callee clobbers every flag; it may read its own live-ins
                    lo = 0
                    use |= consumers.get(call, 0)
                elif kind == "calli":
                    lo = 0
                elif kind == "tail":
                    use |= consumers.get(call, 0)
                v = use | (lo & ~dfn)
                if v != lin[k]:
                    lin[k] = v
                    changed = True
        return lin

    # 1) consumers to a fixpoint (a caller of a consumer may itself become one)
    callers = {}
    for e, s in funcs.items():
        for use, dfn, kind, call, succ, a in s:
            if kind in ("call", "tail") and call in funcs:
                callers.setdefault(call, set()).add(e)
    work = list(funcs)
    inq = set(work)
    lins = {}
    while work:
        e = work.pop()
        inq.discard(e)
        lin = live(e)
        lins[e] = lin
        c = lin[0] if lin else 0
        if funcs[e] and funcs[e][0][5] != e:      # entry is not the lowest address
            k = next((k for k, x in enumerate(funcs[e]) if x[5] == e), 0)
            c = lin[k]
        if c != consumers[e]:
            consumers[e] = c
            for p in callers.get(e, ()):
                if p not in inq:
                    work.append(p)
                    inq.add(p)

    # 2) flags read after each call site -> reload there, and the callee must store them
    producers = {e: 0 for e in funcs}
    reload = {}
    for e, s in funcs.items():
        lin = lins[e]
        for k, (use, dfn, kind, call, succ, a) in enumerate(s):
            if kind not in ("call", "calli"):
                continue
            after = 0
            for j in succ:
                after |= lin[j]
            if after:
                reload[(e, a)] = after
                if kind == "call" and call in producers:
                    producers[call] |= after
    # a producer that tail-calls passes the obligation on
    changed = True
    while changed:
        changed = False
        for e, s in funcs.items():
            p = producers[e]
            if not p:
                continue
            for use, dfn, kind, call, succ, a in s:
                if kind == "tail" and call in producers and producers[call] | p != producers[call]:
                    producers[call] |= p
                    changed = True
    return consumers, producers, reload
