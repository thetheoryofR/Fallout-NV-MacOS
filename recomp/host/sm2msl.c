// D3D9 shader bytecode -> Metal Shading Language.
//
// Conventions of the generated code (shared with the Metal backend):
//   vertex stage   : stage_in attributes v0..v15 = attribute(n); constants at buffer(20) float4[256],
//                    buffer(21) int4[16], buffer(22) uint[16], buffer(23) VSys; vertex textures
//                    texture(n)/sampler(n) for s0..s3.
//   fragment stage : constants buffer(0) float4[224], buffer(1) int4[16], buffer(2) uint[16],
//                    buffer(3) PSys; textures/samplers texture(n)/sampler(n) for s0..s15.
//   interpolants   : one float4 per semantic, named S<usage>_<index>, matched with [[user(...)]].
// Must be compiled with fast math OFF (D3D relies on inf/NaN behaviour, e.g. rcp(0)).
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2msl.h"

// ---- register types --------------------------------------------------------------------------
enum { RT_TEMP = 0, RT_INPUT, RT_CONST, RT_ADDR /* ps: TEXTURE */, RT_RASTOUT, RT_ATTROUT, RT_TEXCRDOUT /* vs3: OUTPUT */,
       RT_CONSTINT, RT_COLOROUT, RT_DEPTHOUT, RT_SAMPLER, RT_CONST2, RT_CONST3, RT_CONST4, RT_CONSTBOOL, RT_LOOP,
       RT_TEMPFLOAT16, RT_MISCTYPE, RT_LABEL, RT_PREDICATE };

// ---- opcodes ---------------------------------------------------------------------------------
enum { OP_NOP = 0, OP_MOV, OP_ADD, OP_SUB, OP_MAD, OP_MUL, OP_RCP, OP_RSQ, OP_DP3, OP_DP4, OP_MIN, OP_MAX, OP_SLT,
       OP_SGE, OP_EXP, OP_LOG, OP_LIT, OP_DST, OP_LRP, OP_FRC, OP_M4x4, OP_M4x3, OP_M3x4, OP_M3x3, OP_M3x2,
       OP_CALL, OP_CALLNZ, OP_LOOP, OP_RET, OP_ENDLOOP, OP_LABEL, OP_DCL, OP_POW, OP_CRS, OP_SGN, OP_ABS, OP_NRM,
       OP_SINCOS, OP_REP, OP_ENDREP, OP_IF, OP_IFC, OP_ELSE, OP_ENDIF, OP_BREAK, OP_BREAKC, OP_MOVA, OP_DEFB, OP_DEFI,
       OP_TEXCOORD = 64, OP_TEXKILL, OP_TEX, OP_EXPP = 78, OP_LOGP, OP_CND, OP_DEF, OP_CMP = 88, OP_BEM, OP_DP2ADD,
       OP_DSX, OP_DSY, OP_TEXLDD, OP_SETP, OP_TEXLDL, OP_BREAKP, OP_PHASE = 0xFFFD, OP_COMMENT = 0xFFFE, OP_END = 0xFFFF };

typedef struct { int type, num, rel, rel_type, rel_num, rel_comp; uint8_t swz[4]; int mod; } Src;
typedef struct { int type, num, mask, sat, shift; } Dst;
typedef struct {
    int op; uint32_t ctrl; int has_dst; Dst dst; Src src[5]; int nsrc;
    uint32_t imm[4]; int dcl_usage, dcl_index, dcl_tex;
} Insn;

typedef struct {
    char *buf; size_t len, cap;
    char *err; size_t errlen; int failed;
} Out;

static void emit(Out *o, const char *fmt, ...) {
    va_list ap;
    for (;;) {
        va_start(ap, fmt);
        int n = vsnprintf(o->buf + o->len, o->cap - o->len, fmt, ap);
        va_end(ap);
        if (n < 0) return;
        if (o->len + (size_t)n < o->cap) { o->len += (size_t)n; return; }
        o->cap = o->cap * 2 + (size_t)n + 1024;
        o->buf = realloc(o->buf, o->cap);
    }
}
static void fail(Out *o, const char *fmt, ...) {
    if (o->failed) return;
    o->failed = 1;
    va_list ap; va_start(ap, fmt); vsnprintf(o->err, o->errlen, fmt, ap); va_end(ap);
}

// ---- decoding ----------------------------------------------------------------------------------
static int reg_type(uint32_t t) { return (int)(((t >> 28) & 7) | ((t >> 8) & 0x18)); }

// parameter-token counts for shader model 1.x (no length field in the instruction token)
static int sm1_len(int op) {
    switch (op) {
    case OP_NOP: case OP_RET: case OP_ENDLOOP: case OP_ENDREP: case OP_ELSE: case OP_ENDIF: case OP_BREAK:
        return 0;
    case OP_TEXKILL: case OP_TEXCOORD: case OP_CALL: case OP_LABEL: case OP_REP: case OP_IF:
        return 1;
    case OP_MOV: case OP_RCP: case OP_RSQ: case OP_EXP: case OP_LOG: case OP_LIT: case OP_FRC: case OP_EXPP:
    case OP_LOGP: case OP_DCL: case OP_ABS: case OP_NRM: case OP_MOVA: case OP_LOOP: case OP_CALLNZ: case OP_IFC:
    case OP_BREAKC:
        return 2;
    case OP_ADD: case OP_SUB: case OP_MUL: case OP_DP3: case OP_DP4: case OP_MIN: case OP_MAX: case OP_SLT:
    case OP_SGE: case OP_DST: case OP_M4x4: case OP_M4x3: case OP_M3x4: case OP_M3x3: case OP_M3x2: case OP_POW:
    case OP_CRS: case OP_TEX:
        return 3;
    case OP_MAD: case OP_LRP: case OP_CND: case OP_CMP: case OP_DP2ADD: case OP_SGN:
        return 4;
    case OP_DEF:
        return 5;
    }
    return -1;
}

static void dec_src(const uint32_t *p, size_t *i, int sm, Src *s) {
    uint32_t t = p[(*i)++];
    s->type = reg_type(t); s->num = (int)(t & 0x7FF); s->mod = (int)((t >> 24) & 0xF);
    for (int k = 0; k < 4; k++) s->swz[k] = (uint8_t)((t >> (16 + 2 * k)) & 3);
    s->rel = (t & 0x2000) != 0;
    if (s->rel) {
        if (sm >= 2) {
            uint32_t r = p[(*i)++];
            s->rel_type = reg_type(r); s->rel_num = (int)(r & 0x7FF); s->rel_comp = (int)((r >> 16) & 3);
        } else { s->rel_type = RT_ADDR; s->rel_num = 0; s->rel_comp = 0; }
    }
}
static void dec_dst(const uint32_t *p, size_t *i, Dst *d) {
    uint32_t t = p[(*i)++];
    d->type = reg_type(t); d->num = (int)(t & 0x7FF); d->mask = (int)((t >> 16) & 0xF);
    d->sat = ((t >> 20) & 1) != 0; d->shift = (int)((t >> 24) & 0xF);
    if (t & 0x2000) (*i)++;     // relative destination (vs3 o[aL]) — address token skipped
}

static int src_count(int op) {
    switch (op) {
    case OP_MOV: case OP_MOVA: case OP_RCP: case OP_RSQ: case OP_EXP: case OP_LOG: case OP_EXPP: case OP_LOGP: case OP_LIT:
    case OP_FRC: case OP_ABS: case OP_NRM: case OP_DSX: case OP_DSY: return 1;
    case OP_ADD: case OP_SUB: case OP_MUL: case OP_DP3: case OP_DP4: case OP_MIN: case OP_MAX: case OP_SLT: case OP_SGE:
    case OP_DST: case OP_M4x4: case OP_M4x3: case OP_M3x4: case OP_M3x3: case OP_M3x2: case OP_POW: case OP_CRS:
    case OP_TEX: case OP_TEXLDL: case OP_SETP: return 2;
    case OP_MAD: case OP_LRP: case OP_CND: case OP_CMP: case OP_DP2ADD: case OP_SGN: return 3;
    case OP_TEXLDD: return 4;
    }
    return 0;
}

// Decode the whole program into an instruction array.
static Insn *decode(const uint32_t *p, size_t n, int *count, int *is_ps, int *major, int *minor, Out *o) {
    uint32_t v = p[0];
    *is_ps = (v >> 16) == 0xFFFF; *major = (int)((v >> 8) & 0xFF); *minor = (int)(v & 0xFF);
    if ((v >> 16) != 0xFFFF && (v >> 16) != 0xFFFE) { fail(o, "bad version token %08x", v); return NULL; }
    int cap = 256, cnt = 0;
    Insn *ins = calloc((size_t)cap, sizeof *ins);
    size_t i = 1;
    while (i < n) {
        uint32_t t = p[i];
        int op = (int)(t & 0xFFFF);
        if (op == OP_END) break;
        if (op == OP_COMMENT) { i += 1 + ((t >> 16) & 0x7FFF); continue; }
        int len = *major >= 2 ? (int)((t >> 24) & 0xF) : sm1_len(op);
        if (len < 0) { fail(o, "sm1 opcode %d has no length entry", op); break; }
        if (op == OP_PHASE || op == OP_NOP) { i += 1 + (size_t)len; continue; }
        if (cnt == cap) { cap *= 2; ins = realloc(ins, (size_t)cap * sizeof *ins); }
        Insn *x = &ins[cnt]; memset(x, 0, sizeof *x);
        x->op = op; x->ctrl = (t >> 16) & 0xFF;
        size_t start = i + 1, end = start + (size_t)len;
        i = start;
        if (t & 0x10000000) { fail(o, "predicated instruction (op %d) not supported", op); break; }
        switch (op) {
        case OP_DCL: {
            uint32_t d = p[i++];
            x->dcl_usage = (int)(d & 0x1F); x->dcl_index = (int)((d >> 16) & 0xF); x->dcl_tex = (int)((d >> 27) & 0xF);
            x->has_dst = 1; dec_dst(p, &i, &x->dst);
            break;
        }
        case OP_DEF: case OP_DEFI:
            x->has_dst = 1; dec_dst(p, &i, &x->dst);
            for (int k = 0; k < 4; k++) x->imm[k] = p[i++];
            break;
        case OP_DEFB: x->has_dst = 1; dec_dst(p, &i, &x->dst); x->imm[0] = p[i++]; break;
        case OP_CALL: case OP_LABEL: case OP_REP: case OP_IF: case OP_TEXKILL:
            if (op == OP_TEXKILL) { x->has_dst = 1; dec_dst(p, &i, &x->dst); }
            else { dec_src(p, &i, *major, &x->src[0]); x->nsrc = 1; }
            break;
        case OP_CALLNZ: case OP_LOOP: case OP_IFC: case OP_BREAKC:
            dec_src(p, &i, *major, &x->src[0]); dec_src(p, &i, *major, &x->src[1]); x->nsrc = 2;
            break;
        case OP_RET: case OP_ENDLOOP: case OP_ENDREP: case OP_ELSE: case OP_ENDIF: case OP_BREAK: break;
        default: {
            int ns = src_count(op);
            if (op == OP_SINCOS) ns = *major >= 3 ? 1 : 3;
            if (!ns && op != OP_TEXCOORD) { fail(o, "unsupported opcode %d", op); break; }
            x->has_dst = 1; dec_dst(p, &i, &x->dst);
            for (int k = 0; k < ns && i < end; k++) dec_src(p, &i, *major, &x->src[k]);
            x->nsrc = ns;
        }
        }
        if (o->failed) break;
        i = end > i ? end : i;
        cnt++;
    }
    *count = cnt;
    return ins;
}

// ---- translation context -------------------------------------------------------------------------
typedef struct {
    Out *o;
    int is_ps, major, minor;
    Insn *ins; int nins;
    int max_temp;
    // defs
    int has_def[256]; float defv[256][4];
    int has_defi[16]; int defi[16][4];
    int has_defb[16]; int defb[16];
    // declarations
    int vin_usage[16], vin_index[16];
    int out_usage[16], out_index[16];      // vs3 o# semantics
    int pin_usage[16], pin_index[16];      // ps3 v# semantics
    int samp_dim[16];
    uint32_t samplers;
    int uses_addr, uses_loop_aL, writes_depth, ncolor;
    uint16_t io[24]; int nio;
    uint32_t depth_mask;
    int labels[64];                        // instruction index of label l#
} Ctx;

static const char *SWZ = "xyzw";
static void sem_name(char *b, size_t n, int usage, int index) { snprintf(b, n, "S%d_%d", usage, index); }

static int add_io(Ctx *c, int usage, int index) {
    uint16_t k = (uint16_t)(usage << 4 | index);
    for (int i = 0; i < c->nio; i++) if (c->io[i] == k) return i;
    if (c->nio < 24) c->io[c->nio++] = k;
    return c->nio - 1;
}

// register -> MSL lvalue/rvalue (float4 unless noted)
static void reg_name(Ctx *c, char *b, size_t n, int type, int num, int for_write) {
    switch (type) {
    case RT_TEMP: case RT_TEMPFLOAT16: snprintf(b, n, "r%d", num); return;
    case RT_INPUT:
        if (!c->is_ps) { snprintf(b, n, "vin.v%d", num); return; }
        if (c->major >= 3) { char s[16]; sem_name(s, sizeof s, c->pin_usage[num], c->pin_index[num]); snprintf(b, n, "pin.%s", s); return; }
        { char s[16]; sem_name(s, sizeof s, SEM_COLOR, num); snprintf(b, n, "pin.%s", s); return; }
    case RT_CONST: case RT_CONST2: case RT_CONST3: case RT_CONST4: {
        int base = type == RT_CONST ? 0 : type == RT_CONST2 ? 2048 : type == RT_CONST3 ? 4096 : 6144;
        snprintf(b, n, "CF(%d)", base + num); return;
    }
    case RT_ADDR:
        if (c->is_ps) { char s[16]; sem_name(s, sizeof s, SEM_TEXCOORD, num); snprintf(b, n, "pin.%s", s); return; }
        snprintf(b, n, "a0"); return;
    case RT_RASTOUT:
        if (num == 0) snprintf(b, n, "vout.pos"); else if (num == 1) snprintf(b, n, "vout.S%d_0", SEM_FOG);
        else snprintf(b, n, "vout_psize");
        return;
    case RT_ATTROUT: snprintf(b, n, "vout.S%d_%d", SEM_COLOR, num); return;
    case RT_TEXCRDOUT:
        if (c->major >= 3) {
            if (c->out_usage[num] == SEM_POSITION && c->out_index[num] == 0) { snprintf(b, n, "vout.pos"); return; }
            if (c->out_usage[num] == SEM_PSIZE) { snprintf(b, n, "vout_psize"); return; }
            snprintf(b, n, "vout.S%d_%d", c->out_usage[num], c->out_index[num]); return;
        }
        snprintf(b, n, "vout.S%d_%d", SEM_TEXCOORD, num); return;
    case RT_CONSTINT: snprintf(b, n, "CI(%d)", num); return;
    case RT_CONSTBOOL: snprintf(b, n, "CB(%d)", num); return;
    case RT_COLOROUT: snprintf(b, n, "pout.c%d", num); return;
    case RT_DEPTHOUT: snprintf(b, n, "pout.depth"); return;
    case RT_LOOP: snprintf(b, n, "aL"); return;
    case RT_MISCTYPE:
        if (num == 0) snprintf(b, n, "float4(pin.pos.xy - 0.5, 0.0, 1.0)");
        else snprintf(b, n, "float4(pin.face ? 1.0 : -1.0)");
        return;
    case RT_PREDICATE: snprintf(b, n, "p0"); return;
    }
    (void)for_write;
    fail(c->o, "unsupported register type %d", type);
    snprintf(b, n, "float4(0)");
}

static void src_expr(Ctx *c, char *b, size_t n, const Src *s) {
    char base[96];
    if (s->rel && (s->type == RT_CONST || s->type == RT_TEXCRDOUT || s->type == RT_INPUT)) {
        char idx[48];
        if (s->rel_type == RT_LOOP) snprintf(idx, sizeof idx, "aL");
        else snprintf(idx, sizeof idx, "a0.%c", SWZ[s->rel_comp]);
        if (s->type == RT_CONST) { snprintf(base, sizeof base, "CFR(%d + %s)", s->num, idx); c->uses_addr = 1; }
        else { fail(c->o, "relative addressing on register type %d", s->type); snprintf(base, sizeof base, "float4(0)"); }
    } else reg_name(c, base, sizeof base, s->type, s->num, 0);
    if (s->type == RT_ADDR && !c->is_ps) { char t[96]; snprintf(t, sizeof t, "float4(%s)", base); memcpy(base, t, sizeof base); }
    if (s->type == RT_CONSTINT) { char t[96]; snprintf(t, sizeof t, "float4(%s)", base); memcpy(base, t, sizeof base); }
    if (s->type == RT_CONSTBOOL) { char t[96]; snprintf(t, sizeof t, "float4(%s ? 1.0 : 0.0)", base); memcpy(base, t, sizeof base); }
    if (s->type == RT_LOOP) { char t[96]; snprintf(t, sizeof t, "float4(float(aL))"); memcpy(base, t, sizeof base); }
    if (s->type == RT_PREDICATE) { char t[96]; snprintf(t, sizeof t, "float4(p0)"); memcpy(base, t, sizeof base); }
    char sw[8] = "";
    if (!(s->swz[0] == 0 && s->swz[1] == 1 && s->swz[2] == 2 && s->swz[3] == 3))
        snprintf(sw, sizeof sw, ".%c%c%c%c", SWZ[s->swz[0]], SWZ[s->swz[1]], SWZ[s->swz[2]], SWZ[s->swz[3]]);
    char v[192]; snprintf(v, sizeof v, "(%s)%s", base, sw);
    switch (s->mod) {
    case 0: snprintf(b, n, "%s", v); break;
    case 1: snprintf(b, n, "(-%s)", v); break;
    case 2: snprintf(b, n, "(%s - 0.5)", v); break;
    case 3: snprintf(b, n, "(-(%s - 0.5))", v); break;
    case 4: snprintf(b, n, "(%s * 2.0 - 1.0)", v); break;
    case 5: snprintf(b, n, "(-(%s * 2.0 - 1.0))", v); break;
    case 6: snprintf(b, n, "(1.0 - %s)", v); break;
    case 7: snprintf(b, n, "(%s * 2.0)", v); break;
    case 8: snprintf(b, n, "(-(%s * 2.0))", v); break;
    case 9: snprintf(b, n, "(%s / %s.z)", v, v); break;
    case 10: snprintf(b, n, "(%s / %s.w)", v, v); break;
    case 11: snprintf(b, n, "abs(%s)", v); break;
    case 12: snprintf(b, n, "(-abs(%s))", v); break;
    case 13: snprintf(b, n, "(float4(1.0) - %s)", v); break;
    default: fail(c->o, "source modifier %d", s->mod); snprintf(b, n, "%s", v);
    }
}

// write `expr` (float4) to the destination with mask / saturate
static void write_dst(Ctx *c, const Dst *d, const char *expr) {
    char name[96];
    if (d->type == RT_ADDR && !c->is_ps) {           // a0 (mov in vs_1_1 floors, mova rounds)
        for (int k = 0; k < 4; k++) if (d->mask & (1 << k))
            emit(c->o, "  a0.%c = int(%s((%s).%c));\n", SWZ[k], c->major < 2 ? "floor" : "rint", expr, SWZ[k]);
        return;
    }
    if (d->type == RT_PREDICATE) { emit(c->o, "  p0 = (%s) != 0.0;\n", expr); return; }
    reg_name(c, name, sizeof name, d->type, d->num, 1);
    char e[2048];
    if (d->sat) snprintf(e, sizeof e, "saturate(%s)", expr); else snprintf(e, sizeof e, "(%s)", expr);
    if (d->type == RT_RASTOUT && d->num == 1) { emit(c->o, "  %s = float4((%s).x);\n", name, e); return; }   // oFog (scalar)
    if ((d->type == RT_RASTOUT && d->num == 2) || (d->type == RT_TEXCRDOUT && c->major >= 3 && c->out_usage[d->num] == SEM_PSIZE)) {
        emit(c->o, "  %s = (%s).x;\n", name, e); return;
    }
    if (d->type == RT_DEPTHOUT) { emit(c->o, "  %s = (%s).x;\n", name, e); return; }
    if (d->mask == 0xF) { emit(c->o, "  %s = %s;\n", name, e); return; }
    char m[5] = ""; int k2 = 0;
    for (int k = 0; k < 4; k++) if (d->mask & (1 << k)) m[k2++] = SWZ[k];
    m[k2] = 0;
    emit(c->o, "  %s.%s = %s.%s;\n", name, m, e, m);
}

// matrix row k of a matrix source (consecutive registers)
static void row_expr(Ctx *c, char *b, size_t n, const Src *s, int k) { Src r = *s; r.num += k; src_expr(c, b, n, &r); }

static const char *cmp_op(uint32_t ctrl) {
    switch (ctrl & 7) { case 1: return ">"; case 2: return "=="; case 3: return ">="; case 4: return "<"; case 5: return "!="; case 6: return "<="; }
    return "!=";
}

static void emit_body(Ctx *c, int from, int to, int depth);

static void emit_tex(Ctx *c, const Insn *x) {
    char co[512], dx[512], dy[512], res[1024];
    src_expr(c, co, sizeof co, &x->src[0]);
    int s = x->src[1].num;
    int dim = c->samp_dim[s] ? c->samp_dim[s] : 2;
    c->samplers |= 1u << s;
    int depth = (c->depth_mask >> s) & 1;
    const char *crd = dim == 2 ? "xy" : "xyz";
    if (x->op == OP_TEX && (x->ctrl & 1)) {          // texldp: projective
        if (depth) snprintf(res, sizeof res, "float4(t%d.sample_compare(sc%d, (%s).xy / (%s).w, (%s).z / (%s).w))", s, s, co, co, co, co);
        else snprintf(res, sizeof res, "t%d.sample(s%d, (%s).%s / (%s).w)", s, s, co, crd, co);
    } else if (x->op == OP_TEX && (x->ctrl & 2)) {   // texldb: bias in .w
        snprintf(res, sizeof res, "t%d.sample(s%d, (%s).%s, bias((%s).w))", s, s, co, crd, co);
    } else if (x->op == OP_TEXLDL) {
        if (depth) snprintf(res, sizeof res, "float4(t%d.sample_compare(sc%d, (%s).xy, (%s).z, level(0)))", s, s, co, co);
        else snprintf(res, sizeof res, "t%d.sample(s%d, (%s).%s, level((%s).w))", s, s, co, crd, co);
    } else if (x->op == OP_TEXLDD) {
        src_expr(c, dx, sizeof dx, &x->src[2]); src_expr(c, dy, sizeof dy, &x->src[3]);
        snprintf(res, sizeof res, "t%d.sample(s%d, (%s).%s, %s((%s).%s, (%s).%s))", s, s, co, crd,
                 dim == 3 ? "gradientcube" : dim == 4 ? "gradient3d" : "gradient2d", dx, crd, dy, crd);
    } else {
        if (depth) snprintf(res, sizeof res, "float4(t%d.sample_compare(sc%d, (%s).xy, (%s).z))", s, s, co, co);
        else snprintf(res, sizeof res, "t%d.sample(s%d, (%s).%s)", s, s, co, crd);
    }
    if (!c->is_ps && x->op != OP_TEXLDL) fail(c->o, "vertex texture fetch without lod");
    write_dst(c, &x->dst, res);
}

static void emit_insn(Ctx *c, int idx, int depth) {
    const Insn *x = &c->ins[idx];
    char a[512], b[512], d[512], e[2048];
    a[0] = b[0] = d[0] = 0;
    // sampler operands (texld's s#) are not values: emit_tex reads them directly
    if (x->nsrc > 0 && x->src[0].type != RT_SAMPLER) src_expr(c, a, sizeof a, &x->src[0]);
    if (x->nsrc > 1 && x->src[1].type != RT_SAMPLER) src_expr(c, b, sizeof b, &x->src[1]);
    if (x->nsrc > 2 && x->src[2].type != RT_SAMPLER) src_expr(c, d, sizeof d, &x->src[2]);
    switch (x->op) {
    case OP_DCL: case OP_DEF: case OP_DEFI: case OP_DEFB: case OP_LABEL: return;
    case OP_MOV: case OP_MOVA: write_dst(c, &x->dst, a); return;
    case OP_ADD: snprintf(e, sizeof e, "%s + %s", a, b); break;
    case OP_SUB: snprintf(e, sizeof e, "%s - %s", a, b); break;
    case OP_MUL: snprintf(e, sizeof e, "%s * %s", a, b); break;
    case OP_MAD: snprintf(e, sizeof e, "%s * %s + %s", a, b, d); break;
    case OP_RCP: snprintf(e, sizeof e, "float4(1.0 / (%s).x)", a); break;
    case OP_RSQ: snprintf(e, sizeof e, "float4(rsqrt(abs((%s).x)))", a); break;
    case OP_DP3: snprintf(e, sizeof e, "float4(dot((%s).xyz, (%s).xyz))", a, b); break;
    case OP_DP4: snprintf(e, sizeof e, "float4(dot(%s, %s))", a, b); break;
    case OP_MIN: snprintf(e, sizeof e, "min(%s, %s)", a, b); break;
    case OP_MAX: snprintf(e, sizeof e, "max(%s, %s)", a, b); break;
    case OP_SLT: snprintf(e, sizeof e, "select(float4(0.0), float4(1.0), %s < %s)", a, b); break;
    case OP_SGE: snprintf(e, sizeof e, "select(float4(0.0), float4(1.0), %s >= %s)", a, b); break;
    case OP_EXP: snprintf(e, sizeof e, "float4(exp2((%s).x))", a); break;
    case OP_LOG: snprintf(e, sizeof e, "float4(log2(abs((%s).x)))", a); break;
    case OP_EXPP:
        if (c->major < 2) snprintf(e, sizeof e, "d3d_expp((%s).x)", a); else snprintf(e, sizeof e, "float4(exp2((%s).x))", a);
        break;
    case OP_LOGP:
        if (c->major < 2) snprintf(e, sizeof e, "d3d_logp((%s).x)", a); else snprintf(e, sizeof e, "float4(log2(abs((%s).x)))", a);
        break;
    case OP_LIT: snprintf(e, sizeof e, "d3d_lit(%s)", a); break;
    case OP_DST: snprintf(e, sizeof e, "float4(1.0, (%s).y * (%s).y, (%s).z, (%s).w)", a, b, a, b); break;
    case OP_LRP: snprintf(e, sizeof e, "mix(%s, %s, %s)", d, b, a); break;
    case OP_FRC: snprintf(e, sizeof e, "fract(%s)", a); break;
    case OP_POW: snprintf(e, sizeof e, "float4(pow(abs((%s).x), (%s).x))", a, b); break;
    case OP_CRS: snprintf(e, sizeof e, "float4(cross((%s).xyz, (%s).xyz), 0.0)", a, b); break;
    case OP_SGN: snprintf(e, sizeof e, "sign(%s)", a); break;
    case OP_ABS: snprintf(e, sizeof e, "abs(%s)", a); break;
    case OP_NRM: snprintf(e, sizeof e, "d3d_nrm(%s)", a); break;
    case OP_SINCOS: snprintf(e, sizeof e, "float4(cos((%s).x), sin((%s).x), 0.0, 0.0)", a, a); break;
    case OP_CMP: snprintf(e, sizeof e, "select(%s, %s, %s >= 0.0)", d, b, a); break;
    case OP_CND: snprintf(e, sizeof e, "select(%s, %s, %s > 0.5)", d, b, a); break;
    case OP_DP2ADD: snprintf(e, sizeof e, "float4(dot((%s).xy, (%s).xy) + (%s).x)", a, b, d); break;
    case OP_DSX: snprintf(e, sizeof e, "dfdx(%s)", a); break;
    case OP_DSY: snprintf(e, sizeof e, "dfdy(%s)", a); break;
    case OP_SETP: emit(c->o, "  p0 = %s %s %s;\n", a, cmp_op(x->ctrl), b); return;
    case OP_M4x4: case OP_M4x3: case OP_M3x4: case OP_M3x3: case OP_M3x2: {
        int rows = x->op == OP_M4x4 || x->op == OP_M3x4 ? 4 : x->op == OP_M4x3 || x->op == OP_M3x3 ? 3 : 2;
        int three = x->op == OP_M3x4 || x->op == OP_M3x3 || x->op == OP_M3x2;
        char r[4][512];
        for (int k = 0; k < rows; k++) row_expr(c, r[k], sizeof r[k], &x->src[1], k);
        int n = snprintf(e, sizeof e, "float4(");
        for (int k = 0; k < 4; k++) {
            if (k < rows) n += snprintf(e + n, sizeof e - (size_t)n, three ? "dot((%s).xyz, (%s).xyz)" : "dot(%s, %s)", a, r[k]);
            else n += snprintf(e + n, sizeof e - (size_t)n, "0.0");
            n += snprintf(e + n, sizeof e - (size_t)n, k < 3 ? ", " : ")");
        }
        break;
    }
    case OP_TEX: case OP_TEXLDL: case OP_TEXLDD: emit_tex(c, x); return;
    case OP_TEXKILL: {
        char nm[96]; reg_name(c, nm, sizeof nm, x->dst.type, x->dst.num, 0);
        int mask = x->dst.mask ? x->dst.mask : 0xF;
        if (c->major < 2) mask &= 7;
        emit(c->o, "  if (");
        int first = 1;
        for (int k = 0; k < 4; k++) if (mask & (1 << k)) { emit(c->o, "%s(%s).%c < 0.0", first ? "" : " || ", nm, SWZ[k]); first = 0; }
        emit(c->o, ") discard_fragment();\n");
        return;
    }
    case OP_TEXCOORD: fail(c->o, "texcoord (ps_1_x) not supported"); return;
    case OP_IF: emit(c->o, "  if (%s.x != 0.0) {\n", a); return;
    case OP_IFC: emit(c->o, "  if ((%s).x %s (%s).x) {\n", a, cmp_op(x->ctrl), b); return;
    case OP_ELSE: emit(c->o, "  } else {\n"); return;
    case OP_ENDIF: emit(c->o, "  }\n"); return;
    case OP_REP: emit(c->o, "  for (int rep%d = 0; rep%d < CI(%d).x; rep%d++) {\n", depth, depth, x->src[0].num, depth); return;
    case OP_ENDREP: emit(c->o, "  }\n"); return;
    case OP_ENDLOOP: emit(c->o, "  }}\n"); return;
    case OP_LOOP:
        c->uses_loop_aL = 1;
        emit(c->o, "  { aL = CI(%d).y; for (int lp%d = 0; lp%d < CI(%d).x; lp%d++, aL += CI(%d).z) {\n",
             x->src[1].num, depth, depth, x->src[1].num, depth, x->src[1].num);
        return;
    case OP_BREAK: emit(c->o, "  break;\n"); return;
    case OP_BREAKC: emit(c->o, "  if ((%s).x %s (%s).x) break;\n", a, cmp_op(x->ctrl), b); return;
    case OP_CALL: case OP_CALLNZ: {
        int l = x->src[0].num;
        if (l < 0 || l >= 64 || c->labels[l] < 0) { fail(c->o, "call to undefined label %d", l); return; }
        if (depth > 8) { fail(c->o, "call nesting too deep"); return; }
        if (x->op == OP_CALLNZ) emit(c->o, "  if (%s.x != 0.0) {\n", b); else emit(c->o, "  {\n");
        int end = c->labels[l] + 1;
        while (end < c->nins && c->ins[end].op != OP_RET && c->ins[end].op != OP_LABEL) end++;
        emit_body(c, c->labels[l] + 1, end, depth + 1);
        emit(c->o, "  }\n");
        return;
    }
    case OP_RET: return;
    default: fail(c->o, "opcode %d not translated", x->op); return;
    }
    write_dst(c, &x->dst, e);
}

static void emit_body(Ctx *c, int from, int to, int depth) {
    for (int i = from; i < to && !c->o->failed; i++) {
        if (c->ins[i].op == OP_RET || c->ins[i].op == OP_LABEL) {
            // main ends at the first ret/label; anything after is subroutine bodies
            if (depth == 0) return;
            if (c->ins[i].op == OP_RET) return;
        }
        // nested loop/rep depth for unique counter names
        int d = depth;
        for (int k = from; k < i; k++) {
            if (c->ins[k].op == OP_REP || c->ins[k].op == OP_LOOP) d++;
            if (c->ins[k].op == OP_ENDREP || c->ins[k].op == OP_ENDLOOP) d--;
        }
        emit_insn(c, i, d * 16 + depth);
    }
}

// ---- reflection pass -----------------------------------------------------------------------------
static void collect(Ctx *c) {
    for (int i = 0; i < 16; i++) { c->vin_usage[i] = c->vin_index[i] = -1; c->out_usage[i] = -1; c->pin_usage[i] = -1; }
    for (int i = 0; i < 64; i++) c->labels[i] = -1;
    for (int i = 0; i < c->nins; i++) {
        const Insn *x = &c->ins[i];
        if (x->has_dst && (x->dst.type == RT_TEMP || x->dst.type == RT_TEMPFLOAT16) && x->dst.num + 1 > c->max_temp) c->max_temp = x->dst.num + 1;
        for (int k = 0; k < x->nsrc; k++)
            if ((x->src[k].type == RT_TEMP || x->src[k].type == RT_TEMPFLOAT16) && x->src[k].num + 1 > c->max_temp) c->max_temp = x->src[k].num + 1;
        if (x->op == OP_LABEL && x->src[0].num < 64) c->labels[x->src[0].num] = i;
        if (x->op == OP_DEF && x->dst.num < 256) { c->has_def[x->dst.num] = 1; memcpy(c->defv[x->dst.num], x->imm, 16); }
        if (x->op == OP_DEFI && x->dst.num < 16) { c->has_defi[x->dst.num] = 1; memcpy(c->defi[x->dst.num], x->imm, 16); }
        if (x->op == OP_DEFB && x->dst.num < 16) { c->has_defb[x->dst.num] = 1; c->defb[x->dst.num] = (int)x->imm[0]; }
        if (x->has_dst && x->dst.type == RT_DEPTHOUT) c->writes_depth = 1;
        if (x->has_dst && x->dst.type == RT_COLOROUT && x->dst.num + 1 > c->ncolor) c->ncolor = x->dst.num + 1;
        if (x->op != OP_DCL) continue;
        const Dst *d = &x->dst;
        if (d->type == RT_SAMPLER) { c->samp_dim[d->num] = x->dcl_tex == 2 ? 2 : x->dcl_tex == 3 ? 3 : x->dcl_tex == 4 ? 4 : 2; continue; }
        if (!c->is_ps && d->type == RT_INPUT && d->num < 16) { c->vin_usage[d->num] = x->dcl_usage; c->vin_index[d->num] = x->dcl_index; }
        if (!c->is_ps && d->type == RT_TEXCRDOUT && d->num < 16 && c->major >= 3) { c->out_usage[d->num] = x->dcl_usage; c->out_index[d->num] = x->dcl_index; }
        if (c->is_ps && d->type == RT_INPUT && d->num < 16) {
            if (c->major >= 3) { c->pin_usage[d->num] = x->dcl_usage; c->pin_index[d->num] = x->dcl_index; }
        }
    }
    if (c->ncolor == 0 && c->is_ps) c->ncolor = 1;
    // interpolants
    if (!c->is_ps) {
        if (c->major >= 3) {
            for (int i = 0; i < 16; i++)
                if (c->out_usage[i] >= 0 && !(c->out_usage[i] == SEM_POSITION && c->out_index[i] == 0) && c->out_usage[i] != SEM_PSIZE)
                    add_io(c, c->out_usage[i], c->out_index[i]);
        } else {
            for (int i = 0; i < 8; i++) add_io(c, SEM_TEXCOORD, i);   // a 2.x VS exposes all fixed outputs
            add_io(c, SEM_COLOR, 0); add_io(c, SEM_COLOR, 1); add_io(c, SEM_FOG, 0);
        }
    } else {
        if (c->major >= 3) { for (int i = 0; i < 16; i++) if (c->pin_usage[i] >= 0) add_io(c, c->pin_usage[i], c->pin_index[i]); }
        else {
            for (int i = 0; i < c->nins; i++) {
                const Insn *x = &c->ins[i];
                for (int k = 0; k < x->nsrc; k++) {
                    if (x->src[k].type == RT_INPUT) add_io(c, SEM_COLOR, x->src[k].num);
                    if (x->src[k].type == RT_ADDR) add_io(c, SEM_TEXCOORD, x->src[k].num);
                }
                if (x->op == OP_TEXKILL && x->dst.type == RT_ADDR) add_io(c, SEM_TEXCOORD, x->dst.num);
            }
            add_io(c, SEM_FOG, 0);                                       // fixed-function fog input
        }
    }
}

static void fill_info(Ctx *c, SMInfo *info) {
    memset(info, 0, sizeof *info);
    info->is_ps = c->is_ps; info->major = c->major; info->minor = c->minor;
    for (int i = 0; i < 16; i++) { info->in_usage[i] = (int8_t)c->vin_usage[i]; info->in_index[i] = (int8_t)c->vin_index[i]; }
    for (int i = 0; i < c->nio && i < 16; i++) info->io_keys[i] = c->io[i];
    info->n_io = c->nio < 16 ? c->nio : 16;
    for (int i = 0; i < 16; i++) { info->sampler_dim[i] = (uint8_t)c->samp_dim[i]; if (c->samp_dim[i]) info->samplers |= 1u << i; }
    info->writes_depth = c->writes_depth; info->uses_relative = c->uses_addr; info->n_color_out = c->ncolor;
}

// ---- top level -----------------------------------------------------------------------------------
static const char *PRELUDE =
    "#include <metal_stdlib>\nusing namespace metal;\n"
    "static inline float4 d3d_lit(float4 s) { float d = max(s.x, 0.0); float sp = (s.x > 0.0 && s.y > 0.0) ? pow(s.y, clamp(s.w, -127.9961, 127.9961)) : 0.0; return float4(1.0, d, sp, 1.0); }\n"
    "static inline float4 d3d_nrm(float4 s) { float l = dot(s.xyz, s.xyz); return l > 0.0 ? s * rsqrt(l) : float4(0.0); }\n"
    "static inline float4 d3d_expp(float x) { float f = floor(x); return float4(exp2(f), x - f, exp2(x), 1.0); }\n"
    "static inline float4 d3d_logp(float x) { float a = abs(x); if (a == 0.0) return float4(-INFINITY, 1.0, -INFINITY, 1.0); int e; float m = frexp(a, e); return float4(float(e - 1), m * 2.0, log2(a), 1.0); }\n"
    "struct VSys { float4 halfpixel; };\n"
    "struct PSys { uint alpha_func; float alpha_ref; uint fog_mode; uint fog_enable; float4 fog_color; float4 fog_params; uint fog_table; uint pad0, pad1, pad2; };\n";

static void emit_const_helpers(Ctx *c) {
    // float constants: def'd registers are compile-time values, the rest come from the buffer
    emit(c->o, "#define CF(n) CF_##n\n");
    int maxc = c->is_ps ? 224 : 256;
    for (int i = 0; i < maxc; i++) {
        if (c->has_def[i]) {
            float f[4]; memcpy(f, c->defv[i], 16);
            emit(c->o, "#define CF_%d float4(as_type<float>(0x%08xu), as_type<float>(0x%08xu), as_type<float>(0x%08xu), as_type<float>(0x%08xu))\n",
                 i, ((uint32_t *)c->defv[i])[0], ((uint32_t *)c->defv[i])[1], ((uint32_t *)c->defv[i])[2], ((uint32_t *)c->defv[i])[3]);
            (void)f;
        } else emit(c->o, "#define CF_%d cf[%d]\n", i, i);
    }
    emit(c->o, "#define CI(n) CI_##n\n");
    for (int i = 0; i < 16; i++) {
        if (c->has_defi[i]) emit(c->o, "#define CI_%d int4(%d, %d, %d, %d)\n", i, c->defi[i][0], c->defi[i][1], c->defi[i][2], c->defi[i][3]);
        else emit(c->o, "#define CI_%d ci[%d]\n", i, i);
    }
    emit(c->o, "#define CB(n) CB_##n\n");
    for (int i = 0; i < 16; i++) {
        if (c->has_defb[i]) emit(c->o, "#define CB_%d %s\n", i, c->defb[i] ? "true" : "false");
        else emit(c->o, "#define CB_%d (cb[%d] != 0u)\n", i, i);
    }
}

static void emit_relative_getter(Ctx *c) {
    emit(c->o, "static inline float4 cfr(constant float4 *cf, int i) {\n  switch (i) {\n");
    for (int i = 0; i < 256; i++) if (c->has_def[i]) emit(c->o, "  case %d: return CF_%d;\n", i, i);
    emit(c->o, "  default: return (i >= 0 && i < 256) ? cf[i] : float4(0.0);\n  }\n}\n#define CFR(i) cfr(cf, (i))\n");
}

static int run(Ctx *c, const uint32_t *tok, size_t n, Out *o) {
    c->o = o;
    c->ins = decode(tok, n, &c->nins, &c->is_ps, &c->major, &c->minor, o);
    if (!c->ins || o->failed) return 0;
    collect(c);
    return 1;
}

int sm_reflect(const uint32_t *tok, size_t n, SMInfo *info, char *err, size_t errlen) {
    Out o = {calloc(1, 64), 0, 64, err, errlen, 0};
    Ctx c; memset(&c, 0, sizeof c);
    int ok = run(&c, tok, n, &o);
    if (ok) fill_info(&c, info);
    free(c.ins); free(o.buf);
    return ok && !o.failed;
}

char *sm_translate(const uint32_t *tok, size_t n, SMInfo *info, const uint16_t *extra_out, int n_extra, char *err, size_t errlen) {
    Out o = {malloc(1 << 16), 0, 1 << 16, err, errlen, 0};
    o.buf[0] = 0;
    Ctx c; memset(&c, 0, sizeof c);
    if (!run(&c, tok, n, &o)) { free(c.ins); free(o.buf); return NULL; }
    if (info) c.depth_mask = info->depth_mask_in;
    if (!c.is_ps) for (int i = 0; i < n_extra; i++) add_io(&c, extra_out[i] >> 4, extra_out[i] & 15);

    emit(&o, "%s", PRELUDE);
    emit_const_helpers(&c);
    if (c.is_ps) {
        // ---- fragment ----
        emit(&o, "struct PIn {\n  float4 pos [[position]];\n  bool face [[front_facing]];\n");
        for (int i = 0; i < c.nio; i++) { char s[16]; sem_name(s, sizeof s, c.io[i] >> 4, c.io[i] & 15); emit(&o, "  float4 %s [[user(%s)]];\n", s, s); }
        emit(&o, "};\nstruct POut {\n");
        for (int i = 0; i < c.ncolor; i++) emit(&o, "  float4 c%d [[color(%d)]];\n", i, i);
        if (c.writes_depth) emit(&o, "  float depth [[depth(any)]];\n");
        emit(&o, "};\nfragment POut pmain(PIn pin [[stage_in]], constant float4 *cf [[buffer(0)]], constant int4 *ci [[buffer(1)]],\n"
                 "  constant uint *cb [[buffer(2)]], constant PSys &sys [[buffer(3)]]");
        for (int s = 0; s < 16; s++) {
            int used = 0;
            for (int i = 0; i < c.nins; i++) if ((c.ins[i].op == OP_TEX || c.ins[i].op == OP_TEXLDL || c.ins[i].op == OP_TEXLDD) && c.ins[i].src[1].num == s) used = 1;
            if (!used) continue;
            int dim = c.samp_dim[s] ? c.samp_dim[s] : 2;
            if ((c.depth_mask >> s) & 1)
                emit(&o, ",\n  depth2d<float> t%d [[texture(%d)]], sampler s%d [[sampler(%d)]], sampler sc%d [[sampler(%d)]]", s, s, s, s, s, s + 16);
            else
                emit(&o, ",\n  %s<float> t%d [[texture(%d)]], sampler s%d [[sampler(%d)]]", dim == 3 ? "texturecube" : dim == 4 ? "texture3d" : "texture2d", s, s, s, s);
        }
        emit(&o, ") {\n  POut pout;\n");
        for (int i = 0; i < c.ncolor; i++) emit(&o, "  pout.c%d = float4(0.0);\n", i);
        if (c.writes_depth) emit(&o, "  pout.depth = pin.pos.z;\n");
        for (int i = 0; i < (c.max_temp > 32 ? 32 : c.max_temp); i++) emit(&o, "  float4 r%d = float4(0.0);\n", i);
        emit(&o, "  int aL = 0; bool4 p0 = false; (void)aL; (void)p0;\n");
        emit_body(&c, 0, c.nins, 0);
        // fixed-function fog (ps < 3) and alpha test
        if (c.major < 3)
            emit(&o, "  if (sys.fog_enable != 0u) {\n"
                     "    float f;\n"
                     "    if (sys.fog_table == 0u) f = saturate(pin.S%d_0.x);\n"
                     "    else { float z = pin.pos.z;\n"
                     "      f = sys.fog_mode == 3u ? saturate((sys.fog_params.y - z) / (sys.fog_params.y - sys.fog_params.x))\n"
                     "        : sys.fog_mode == 1u ? exp(-z * sys.fog_params.z) : exp(-(z * sys.fog_params.z) * (z * sys.fog_params.z)); }\n"
                     "    pout.c0.rgb = mix(sys.fog_color.rgb, pout.c0.rgb, f);\n  }\n", SEM_FOG);
        emit(&o, "  if (sys.alpha_func != 8u) {\n"
                 "    float a = pout.c0.a, r = sys.alpha_ref; bool pass;\n"
                 "    switch (sys.alpha_func) { case 1u: pass = false; break; case 2u: pass = a < r; break; case 3u: pass = a == r; break;\n"
                 "      case 4u: pass = a <= r; break; case 5u: pass = a > r; break; case 6u: pass = a != r; break; case 7u: pass = a >= r; break; default: pass = true; }\n"
                 "    if (!pass) discard_fragment();\n  }\n");
        emit(&o, "  return pout;\n}\n");
    } else {
        // ---- vertex ----
        if (c.uses_addr || 1) emit_relative_getter(&c);
        emit(&o, "struct VIn {\n");
        for (int i = 0; i < 16; i++) if (c.vin_usage[i] >= 0) emit(&o, "  float4 v%d [[attribute(%d)]];\n", i, i);
        emit(&o, "};\nstruct VOut {\n  float4 pos [[position]];\n");
        for (int i = 0; i < c.nio; i++) { char s[16]; sem_name(s, sizeof s, c.io[i] >> 4, c.io[i] & 15); emit(&o, "  float4 %s [[user(%s)]];\n", s, s); }
        emit(&o, "  float psize [[point_size]];\n};\n");
        emit(&o, "vertex VOut vmain(VIn vin [[stage_in]], constant float4 *cf [[buffer(20)]], constant int4 *ci [[buffer(21)]],\n"
                 "  constant uint *cb [[buffer(22)]], constant VSys &sys [[buffer(23)]]");
        for (int s = 0; s < 4; s++) {
            int used = 0;
            for (int i = 0; i < c.nins; i++) if (c.ins[i].op == OP_TEXLDL && c.ins[i].src[1].num == s) used = 1;
            if (used) emit(&o, ",\n  texture2d<float> t%d [[texture(%d)]], sampler s%d [[sampler(%d)]]", s, s, s, s);
        }
        emit(&o, ") {\n  VOut vout;\n  vout.pos = float4(0.0);\n  float vout_psize = 1.0;\n");
        for (int i = 0; i < c.nio; i++) {
            char s[16]; sem_name(s, sizeof s, c.io[i] >> 4, c.io[i] & 15);
            // D3D: unwritten color outputs read as white, fog as "no fog", the rest as 0
            const char *def = (c.io[i] >> 4) == SEM_COLOR ? "float4(1.0)" : (c.io[i] >> 4) == SEM_FOG ? "float4(1.0)" : "float4(0.0)";
            emit(&o, "  vout.%s = %s;\n", s, def);
        }
        for (int i = 0; i < (c.max_temp > 32 ? 32 : c.max_temp); i++) emit(&o, "  float4 r%d = float4(0.0);\n", i);
        emit(&o, "  int4 a0 = int4(0); int aL = 0; bool4 p0 = false; (void)a0; (void)aL; (void)p0;\n");
        emit_body(&c, 0, c.nins, 0);
        emit(&o, "  vout.pos.xy += sys.halfpixel.xy * vout.pos.w;     // D3D9 pixel centres\n");
        emit(&o, "  vout.psize = vout_psize;\n  return vout;\n}\n");
    }
    if (info) fill_info(&c, info);
    free(c.ins);
    if (o.failed) { free(o.buf); return NULL; }
    return o.buf;
}
