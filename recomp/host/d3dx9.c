// d3dx9_38 subset FNV imports: D3DX math (row-major, v*M), DDS loading from memory, buffers,
// shader profile strings. Runtime HLSL compile/assemble report failure until something needs them.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "com.h"

uint32_t d3d9_create_texture(uint32_t dev, int cube, uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t fmt, uint32_t pool);
uint32_t d3d9_texture_level_data(uint32_t tex, uint32_t face, uint32_t level, uint32_t *pitch, uint32_t *size);
void d3d9_texture_dirty(uint32_t tex);

static float *M(uint32_t a) { return (float *)(void *)(MEM + a); }
static float FARG(CPU *c, int i) { uint32_t b = ARG(c, i); float f; memcpy(&f, &b, 4); return f; }

static void mul4(float *o, const float *a, const float *b) {
    float t[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            t[4 * i + j] = a[4 * i] * b[j] + a[4 * i + 1] * b[4 + j] + a[4 * i + 2] * b[8 + j] + a[4 * i + 3] * b[12 + j];
    memcpy(o, t, 64);
}
static void D3DXMatrixMultiply_(CPU *c) { mul4(M(ARG(c, 0)), M(ARG(c, 1)), M(ARG(c, 2))); RET(c, ARG(c, 0), 3); }
static void transpose(float *o, const float *a) { float t[16]; for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) t[4 * i + j] = a[4 * j + i]; memcpy(o, t, 64); }
static void D3DXMatrixTranspose_(CPU *c) { transpose(M(ARG(c, 0)), M(ARG(c, 1))); RET(c, ARG(c, 0), 2); }
static void D3DXMatrixMultiplyTranspose_(CPU *c) { float t[16]; mul4(t, M(ARG(c, 1)), M(ARG(c, 2))); transpose(M(ARG(c, 0)), t); RET(c, ARG(c, 0), 3); }
static void D3DXMatrixInverse_(CPU *c) {
    const float *m = M(ARG(c, 2)); double inv[16], det;
    inv[0] = m[5]*m[10]*m[15] - m[5]*m[11]*m[14] - m[9]*m[6]*m[15] + m[9]*m[7]*m[14] + m[13]*m[6]*m[11] - m[13]*m[7]*m[10];
    inv[4] = -m[4]*m[10]*m[15] + m[4]*m[11]*m[14] + m[8]*m[6]*m[15] - m[8]*m[7]*m[14] - m[12]*m[6]*m[11] + m[12]*m[7]*m[10];
    inv[8] = m[4]*m[9]*m[15] - m[4]*m[11]*m[13] - m[8]*m[5]*m[15] + m[8]*m[7]*m[13] + m[12]*m[5]*m[11] - m[12]*m[7]*m[9];
    inv[12] = -m[4]*m[9]*m[14] + m[4]*m[10]*m[13] + m[8]*m[5]*m[14] - m[8]*m[6]*m[13] - m[12]*m[5]*m[10] + m[12]*m[6]*m[9];
    inv[1] = -m[1]*m[10]*m[15] + m[1]*m[11]*m[14] + m[9]*m[2]*m[15] - m[9]*m[3]*m[14] - m[13]*m[2]*m[11] + m[13]*m[3]*m[10];
    inv[5] = m[0]*m[10]*m[15] - m[0]*m[11]*m[14] - m[8]*m[2]*m[15] + m[8]*m[3]*m[14] + m[12]*m[2]*m[11] - m[12]*m[3]*m[10];
    inv[9] = -m[0]*m[9]*m[15] + m[0]*m[11]*m[13] + m[8]*m[1]*m[15] - m[8]*m[3]*m[13] - m[12]*m[1]*m[11] + m[12]*m[3]*m[9];
    inv[13] = m[0]*m[9]*m[14] - m[0]*m[10]*m[13] - m[8]*m[1]*m[14] + m[8]*m[2]*m[13] + m[12]*m[1]*m[10] - m[12]*m[2]*m[9];
    inv[2] = m[1]*m[6]*m[15] - m[1]*m[7]*m[14] - m[5]*m[2]*m[15] + m[5]*m[3]*m[14] + m[13]*m[2]*m[7] - m[13]*m[3]*m[6];
    inv[6] = -m[0]*m[6]*m[15] + m[0]*m[7]*m[14] + m[4]*m[2]*m[15] - m[4]*m[3]*m[14] - m[12]*m[2]*m[7] + m[12]*m[3]*m[6];
    inv[10] = m[0]*m[5]*m[15] - m[0]*m[7]*m[13] - m[4]*m[1]*m[15] + m[4]*m[3]*m[13] + m[12]*m[1]*m[7] - m[12]*m[3]*m[5];
    inv[14] = -m[0]*m[5]*m[14] + m[0]*m[6]*m[13] + m[4]*m[1]*m[14] - m[4]*m[2]*m[13] - m[12]*m[1]*m[6] + m[12]*m[2]*m[5];
    inv[3] = -m[1]*m[6]*m[11] + m[1]*m[7]*m[10] + m[5]*m[2]*m[11] - m[5]*m[3]*m[10] - m[9]*m[2]*m[7] + m[9]*m[3]*m[6];
    inv[7] = m[0]*m[6]*m[11] - m[0]*m[7]*m[10] - m[4]*m[2]*m[11] + m[4]*m[3]*m[10] + m[8]*m[2]*m[7] - m[8]*m[3]*m[6];
    inv[11] = -m[0]*m[5]*m[11] + m[0]*m[7]*m[9] + m[4]*m[1]*m[11] - m[4]*m[3]*m[9] - m[8]*m[1]*m[7] + m[8]*m[3]*m[5];
    inv[15] = m[0]*m[5]*m[10] - m[0]*m[6]*m[9] - m[4]*m[1]*m[10] + m[4]*m[2]*m[9] + m[8]*m[1]*m[6] - m[8]*m[2]*m[5];
    det = m[0] * inv[0] + m[1] * inv[4] + m[2] * inv[8] + m[3] * inv[12];
    if (ARG(c, 1)) { float d = (float)det; memcpy(MEM + ARG(c, 1), &d, 4); }
    if (det == 0) { RET(c, 0, 3); return; }
    float *o = M(ARG(c, 0));
    for (int i = 0; i < 16; i++) o[i] = (float)(inv[i] / det);
    RET(c, ARG(c, 0), 3);
}
static void rot(float *o, int axis, float a) {
    float s = sinf(a), k = cosf(a);
    memset(o, 0, 64); o[0] = o[5] = o[10] = o[15] = 1;
    if (axis == 0) { o[5] = k; o[6] = s; o[9] = -s; o[10] = k; }
    if (axis == 1) { o[0] = k; o[2] = -s; o[8] = s; o[10] = k; }
    if (axis == 2) { o[0] = k; o[1] = s; o[4] = -s; o[5] = k; }
}
static void D3DXMatrixRotationYawPitchRoll_(CPU *c) {
    float z[16], x[16], y[16], t[16];
    rot(z, 2, FARG(c, 3)); rot(x, 0, FARG(c, 2)); rot(y, 1, FARG(c, 1));
    mul4(t, z, x); mul4(M(ARG(c, 0)), t, y);
    RET(c, ARG(c, 0), 4);
}
static void vecmat(float *o, const float *v, const float *m, int n, float w) {
    float x = v[0], y = v[1], z = v[2], ww = n == 4 ? v[3] : w;
    float r[4];
    for (int j = 0; j < 4; j++) r[j] = x * m[j] + y * m[4 + j] + z * m[8 + j] + ww * m[12 + j];
    memcpy(o, r, 16);
}
static void D3DXVec3TransformCoord_(CPU *c) {
    float r[4]; vecmat(r, M(ARG(c, 1)), M(ARG(c, 2)), 3, 1);
    float *o = M(ARG(c, 0)); o[0] = r[0] / r[3]; o[1] = r[1] / r[3]; o[2] = r[2] / r[3];
    RET(c, ARG(c, 0), 3);
}
static void D3DXVec3TransformNormal_(CPU *c) { float r[4]; vecmat(r, M(ARG(c, 1)), M(ARG(c, 2)), 3, 0); memcpy(M(ARG(c, 0)), r, 12); RET(c, ARG(c, 0), 3); }
static void D3DXVec4Transform_(CPU *c) { float r[4]; vecmat(r, M(ARG(c, 1)), M(ARG(c, 2)), 4, 0); memcpy(M(ARG(c, 0)), r, 16); RET(c, ARG(c, 0), 3); }
static void D3DXVec3Normalize_(CPU *c) {
    const float *v = M(ARG(c, 1)); float l = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    float *o = M(ARG(c, 0));
    if (l == 0) { o[0] = o[1] = o[2] = 0; } else { float x = v[0] / l, y = v[1] / l, z = v[2] / l; o[0] = x; o[1] = y; o[2] = z; }
    RET(c, ARG(c, 0), 2);
}
static void D3DXPlaneTransform_(CPU *c) { float r[4]; vecmat(r, M(ARG(c, 1)), M(ARG(c, 2)), 4, 0); memcpy(M(ARG(c, 0)), r, 16); RET(c, ARG(c, 0), 3); }
static void D3DXPlaneNormalize_(CPU *c) {
    const float *p = M(ARG(c, 1)); float l = sqrtf(p[0] * p[0] + p[1] * p[1] + p[2] * p[2]);
    float *o = M(ARG(c, 0)), q[4] = {p[0], p[1], p[2], p[3]};
    for (int i = 0; i < 4; i++) o[i] = l ? q[i] / l : 0;
    RET(c, ARG(c, 0), 2);
}

// ---- ID3DXBuffer -------------------------------------------------------------------------------
static uint32_t vt_buf;
static void Buf_GetBufferPointer(CPU *c) { RET(c, G32(COM_DATA(COM_THIS(c))), 1); }
static void Buf_GetBufferSize(CPU *c) { RET(c, G32(COM_DATA(COM_THIS(c)) + 4), 1); }
static void Buf_QI(CPU *c) { P32(ARG(c, 2), COM_THIS(c)); RET(c, 0, 3); }
static const ComMethod buf_methods[] = {{"QueryInterface", Buf_QI, 2}, {"AddRef", com_AddRef, 0}, {"Release", com_Release, 0},
                                        {"GetBufferPointer", Buf_GetBufferPointer, 0}, {"GetBufferSize", Buf_GetBufferSize, 0}};
uint32_t d3dx_buffer(uint32_t size) {
    if (!vt_buf) vt_buf = com_vtable("ID3DXBuffer", buf_methods, 5);
    uint32_t b = com_new(vt_buf, 8);
    P32(COM_DATA(b), gmalloc(size ? size : 4)); P32(COM_DATA(b) + 4, size);
    return b;
}
static void D3DXCreateBuffer_(CPU *c) { P32(ARG(c, 1), d3dx_buffer(ARG(c, 0))); RET(c, 0, 2); }

static uint32_t str_vs, str_ps;
static uint32_t gstr(const char *s) { uint32_t n = (uint32_t)strlen(s) + 1, p = gmalloc(n); memcpy(MEM + p, s, n); return p; }
static void D3DXGetVertexShaderProfile_(CPU *c) { if (!str_vs) str_vs = gstr("vs_3_0"); RET(c, str_vs, 1); }
static void D3DXGetPixelShaderProfile_(CPU *c) { if (!str_ps) str_ps = gstr("ps_3_0"); RET(c, str_ps, 1); }

#define D3DXERR_INVALIDDATA 0x88760B59u
#define E_FAIL 0x80004005u
static void fail_compile(CPU *c, int nargs, int err_arg, int out_arg, const char *what) {
    fprintf(stderr, "[d3dx] %s -> E_FAIL (runtime shader compilation not implemented)\n", what);
    if (out_arg >= 0 && ARG(c, out_arg)) P32(ARG(c, out_arg), 0);
    if (err_arg >= 0 && ARG(c, err_arg)) P32(ARG(c, err_arg), 0);
    RET(c, E_FAIL, nargs);
}
static void D3DXCompileShader_(CPU *c) { fail_compile(c, 10, 8, 7, "D3DXCompileShader"); }
static void D3DXCompileShaderFromFileA_(CPU *c) { fprintf(stderr, "[d3dx] file %s\n", GSTR(ARG(c, 0))); fail_compile(c, 9, 7, 6, "D3DXCompileShaderFromFileA"); }
static void D3DXAssembleShader_(CPU *c) { fail_compile(c, 7, 6, 5, "D3DXAssembleShader"); }
static void D3DXAssembleShaderFromFileA_(CPU *c) { fail_compile(c, 6, 5, 4, "D3DXAssembleShaderFromFileA"); }
static void D3DXGetShaderConstantTable_(CPU *c) { P32(ARG(c, 1), 0); RET(c, E_FAIL, 2); }

// ---- DDS ---------------------------------------------------------------------------------------
typedef struct { uint32_t w, h, depth, mips, fmt, cube, volume, data_off; } DDSInfo;
#define FCC(a, b, c_, d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c_) << 16) | ((uint32_t)(d) << 24))
static int dds_parse(uint32_t p, uint32_t n, DDSInfo *o) {
    if (n < 128 || G32(p) != FCC('D', 'D', 'S', ' ')) return 0;
    uint32_t h = p + 4;
    o->h = G32(h + 8); o->w = G32(h + 12); o->depth = G32(h + 20); o->mips = G32(h + 24) ? G32(h + 24) : 1;
    uint32_t pf = h + 72, pff = G32(pf + 4), fourcc = G32(pf + 8), bits = G32(pf + 12);
    uint32_t rm = G32(pf + 16), gm = G32(pf + 20), bm = G32(pf + 24), am = G32(pf + 28);
    uint32_t caps2 = G32(h + 108);
    o->cube = (caps2 & 0x200) != 0; o->volume = (caps2 & 0x200000) != 0;
    o->data_off = 128;
    if (pff & 4) o->fmt = fourcc;                               // DDPF_FOURCC (DXTn, ATIn, or a D3DFMT value)
    else if (bits == 32) o->fmt = rm == 0xFF0000 ? (am ? 21 : 22) : (am ? 32 : 33);
    else if (bits == 24) o->fmt = 20;
    else if (bits == 16) o->fmt = (pff & 0x20000) ? 51 : gm == 0x7E0 ? 23 : am == 0x8000 ? 25 : am == 0xF000 ? 26 : 24;
    else if (bits == 8) o->fmt = (pff & 0x20000) ? 50 : 28;
    else return 0;
    (void)bm;
    return 1;
}
static void D3DXGetImageInfoFromFileInMemory_(CPU *c) {
    DDSInfo d; uint32_t info = ARG(c, 2);
    if (!dds_parse(ARG(c, 0), ARG(c, 1), &d)) { RET(c, D3DXERR_INVALIDDATA, 3); return; }
    P32(info, d.w); P32(info + 4, d.h); P32(info + 8, d.depth ? d.depth : 1); P32(info + 12, d.mips); P32(info + 16, d.fmt);
    P32(info + 20, d.cube ? 5 : d.volume ? 4 : 3); P32(info + 24, 4 /* D3DXIFF_DDS */);
    RET(c, 0, 3);
}
static uint32_t dds_load(uint32_t dev, uint32_t src, uint32_t n, int want_cube) {
    DDSInfo d;
    if (!dds_parse(src, n, &d)) return 0;
    uint32_t faces = want_cube && d.cube ? 6 : 1;
    uint32_t tex = d3d9_create_texture(dev, faces == 6, d.w, d.h, d.mips, 0, d.fmt, 1 /* MANAGED */);
    uint32_t off = src + d.data_off, end = src + n;
    for (uint32_t f = 0; f < faces; f++)
        for (uint32_t l = 0; l < d.mips; l++) {
            uint32_t pitch, size, dst = d3d9_texture_level_data(tex, f, l, &pitch, &size);
            if (!dst) continue;
            uint32_t take = off + size <= end ? size : (off < end ? end - off : 0);
            memcpy(MEM + dst, MEM + off, take);
            off += size;
        }
    d3d9_texture_dirty(tex);
    return tex;
}
static void D3DXCreateTextureFromFileInMemory_(CPU *c) {
    uint32_t t = dds_load(ARG(c, 0), ARG(c, 1), ARG(c, 2), 0);
    if (!t) { fprintf(stderr, "[d3dx] CreateTextureFromFileInMemory: not a DDS this loader understands\n"); RET(c, D3DXERR_INVALIDDATA, 4); return; }
    P32(ARG(c, 3), t); RET(c, 0, 4);
}
static void D3DXCreateCubeTextureFromFileInMemory_(CPU *c) {
    uint32_t t = dds_load(ARG(c, 0), ARG(c, 1), ARG(c, 2), 1);
    if (!t) { RET(c, D3DXERR_INVALIDDATA, 4); return; }
    P32(ARG(c, 3), t); RET(c, 0, 4);
}
static void D3DXCreateVolumeTextureFromFileInMemory_(CPU *c) {
    uint32_t t = dds_load(ARG(c, 0), ARG(c, 1), ARG(c, 2), 0);
    if (!t) { RET(c, D3DXERR_INVALIDDATA, 4); return; }
    P32(ARG(c, 3), t); RET(c, 0, 4);
}
static void D3DXLoadSurfaceFromSurface_(CPU *c) { RET(c, 0, 8); }    // TODO(M3): blit through the backend
static void D3DXSaveTextureToFileA_(CPU *c) { fprintf(stderr, "[d3dx] SaveTextureToFile(%s) ignored\n", GSTR(ARG(c, 0))); RET(c, 0, 4); }

#define S(n) {#n, n##_},
const ShimTable d3dx_shims = { (const Shim[]){
    S(D3DXMatrixMultiply) S(D3DXMatrixTranspose) S(D3DXMatrixMultiplyTranspose) S(D3DXMatrixInverse)
    S(D3DXMatrixRotationYawPitchRoll) S(D3DXVec3TransformCoord) S(D3DXVec3TransformNormal) S(D3DXVec4Transform)
    S(D3DXVec3Normalize) S(D3DXPlaneTransform) S(D3DXPlaneNormalize) S(D3DXCreateBuffer) S(D3DXGetVertexShaderProfile)
    S(D3DXGetPixelShaderProfile) S(D3DXCompileShader) S(D3DXCompileShaderFromFileA) S(D3DXAssembleShader)
    S(D3DXAssembleShaderFromFileA) S(D3DXGetShaderConstantTable) S(D3DXGetImageInfoFromFileInMemory)
    S(D3DXCreateTextureFromFileInMemory) S(D3DXCreateCubeTextureFromFileInMemory)
    S(D3DXCreateVolumeTextureFromFileInMemory) S(D3DXLoadSurfaceFromSurface) S(D3DXSaveTextureToFileA)
}, 25 };
