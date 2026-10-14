// Direct3D 9 runtime. Every interface is a guest COM object whose vtable comes from the generated
// layout table (gen/d3d9_methods.h); methods not overridden here return D3D_OK and pop correctly.
// Resources live in guest memory so Lock() hands the game real pointers; state lives in the device.
// The backend (null now, Metal in M3) consumes resources + state at draw/present time.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "com.h"
#include "d3d9_backend.h"
#include "gen/d3d9_methods.h"

#define D3D_OK 0
#define D3DERR_NOTAVAILABLE 0x8876086Au
#define D3DERR_INVALIDCALL 0x8876086Cu
#define E_NOINTERFACE 0x80004002u
#define S_FALSE 1

static int trace_d3d(void) { static int t = -1; if (t < 0) t = getenv("FNV_TRACE_D3D") != NULL; return t; }

// ---- generic method tables -----------------------------------------------------------------------
static void ok0(CPU *c) { RET(c, 0, 1); }
static void ok1(CPU *c) { RET(c, 0, 2); }
static void ok2(CPU *c) { RET(c, 0, 3); }
static void ok3(CPU *c) { RET(c, 0, 4); }
static void ok4(CPU *c) { RET(c, 0, 5); }
static void ok5(CPU *c) { RET(c, 0, 6); }
static void ok6(CPU *c) { RET(c, 0, 7); }
static void ok7(CPU *c) { RET(c, 0, 8); }
static void ok8(CPU *c) { RET(c, 0, 9); }
static void ok9(CPU *c) { RET(c, 0, 10); }
static void ok10(CPU *c) { RET(c, 0, 11); }
static void ok11(CPU *c) { RET(c, 0, 12); }
static void ok12(CPU *c) { RET(c, 0, 13); }
static const ShimFn okn[] = {ok0, ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8, ok9, ok10, ok11, ok12};

typedef struct { const char *name; ShimFn fn; } Ov;
static uint32_t build_vtable(const char *iface, const char *const *names, const unsigned char *nargs, int n, const Ov *ov, int nov) {
    ComMethod m[160];
    for (int i = 0; i < n; i++) {
        m[i].name = names[i]; m[i].nargs = nargs[i]; m[i].fn = nargs[i] < 13 ? okn[nargs[i]] : NULL;
        for (int k = 0; k < nov; k++) if (!strcmp(ov[k].name, names[i])) m[i].fn = ov[k].fn;
    }
    return com_vtable(iface, m, n);
}
#define VT(iface, ovs) build_vtable(#iface, iface##_names, iface##_nargs, iface##_COUNT, ovs, (int)(sizeof ovs / sizeof *ovs))

// ---- common IUnknown / resource helpers ------------------------------------------------------------
// every object: [vtbl][ref][kind][device][...kind data]
enum { K_TEX = 1, K_CUBE, K_VOL, K_SURF, K_VB, K_IB, K_DECL, K_VS, K_PS, K_QUERY, K_SB, K_SWAP, K_VOLUME };
#define OBJ_KIND(o) G32((o) + 8)
#define OBJ_DEV(o) G32((o) + 12)
#define OBJ_F(o, i) ((o) + 16 + 4 * (i))           // kind-specific fields

static uint32_t vt_d3d, vt_dev, vt_tex, vt_cube, vt_voltex, vt_surf, vt_vb, vt_ib, vt_decl, vt_vs, vt_ps, vt_query, vt_sb, vt_swap, vt_volume;
static uint32_t the_device;

static uint32_t newobj(uint32_t vt, int kind, uint32_t dev, int nfields) {
    uint32_t o = gmalloc(16 + 4u * (uint32_t)nfields);
    P32(o, vt); P32(o + 4, 1); P32(o + 8, (uint32_t)kind); P32(o + 12, dev);
    return o;
}
static void addref(uint32_t o) { if (o) P32(o + 4, G32(o + 4) + 1); }
static void Unk_QueryInterface(CPU *c) { addref(COM_THIS(c)); P32(ARG(c, 2), COM_THIS(c)); RET(c, 0, 3); }
static void Unk_AddRef(CPU *c) { addref(COM_THIS(c)); RET(c, G32(COM_THIS(c) + 4), 1); }
// Released resources are freed (guest memory back to the heap) a few frames later, and only once
// nothing in the device state still points at them: D3D9's Set* calls hold a reference that this
// layer doesn't count, and draws already encoded may still read the guest object. Shaders and
// declarations are never freed — the pipeline cache is keyed by their addresses.
static void bury(uint32_t o);
static void Unk_Release(CPU *c) {
    uint32_t o = COM_THIS(c), r = G32(o + 4);
    if (!r) { RET(c, 0, 1); return; }          // over-release: ignore (never free twice)
    r--;
    P32(o + 4, r);
    if (!r) { d3d_backend_release(o); bury(o); }
    RET(c, r, 1);
}
static void Res_GetDevice(CPU *c) { uint32_t d = OBJ_DEV(COM_THIS(c)); addref(d); P32(ARG(c, 1), d); RET(c, 0, 2); }
static void Res_GetPriority(CPU *c) { RET(c, 0, 1); }
static void Res_GetType(CPU *c) {
    int k = (int)OBJ_KIND(COM_THIS(c));
    RET(c, k == K_SURF ? 1 : k == K_VOLUME ? 2 : k == K_TEX ? 3 : k == K_VOL ? 4 : k == K_CUBE ? 5 : k == K_VB ? 6 : 7, 1);
}

// ---- formats -------------------------------------------------------------------------------------
#define FOURCC(a, b, c_, d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c_) << 16) | ((uint32_t)(d) << 24))
int d3d_fmt_block(uint32_t f) {     // bytes per 4x4 block for compressed formats, else 0
    if (f == FOURCC('D', 'X', 'T', '1') || f == FOURCC('A', 'T', 'I', '1')) return 8;
    if (f == FOURCC('D', 'X', 'T', '2') || f == FOURCC('D', 'X', 'T', '3') || f == FOURCC('D', 'X', 'T', '4') ||
        f == FOURCC('D', 'X', 'T', '5') || f == FOURCC('A', 'T', 'I', '2')) return 16;
    return 0;
}
int d3d_fmt_bpp(uint32_t f) {       // bytes per pixel for uncompressed formats
    switch (f) {
    case 20: return 3;                                   // R8G8B8
    case 21: case 22: case 32: case 33: case 34: case 35: case 31: case 77: case 75: case 71: case 114: case 112:
    case 63: case 62: case 65: case 67: return 4;
    case 23: case 24: case 25: case 26: case 29: case 30: case 51: case 60: case 80: case 70: case 81: case 111:
    case 41: return 2;
    case 28: case 50: case 52: return 1;
    case 36: case 113: case 115: case 64: return 8;
    case 116: return 16;
    }
    if (f == FOURCC('I', 'N', 'T', 'Z')) return 4;
    if (f == FOURCC('N', 'U', 'L', 'L')) return 4;
    return 4;
}
static void level_layout(uint32_t fmt, uint32_t w, uint32_t h, uint32_t *pitch, uint32_t *size) {
    int blk = d3d_fmt_block(fmt);
    if (blk) { uint32_t bw = (w + 3) / 4, bh = (h + 3) / 4; *pitch = bw * (uint32_t)blk; *size = *pitch * bh; }
    else { *pitch = w * (uint32_t)d3d_fmt_bpp(fmt); *size = *pitch * h; }
}

// ---- surfaces ------------------------------------------------------------------------------------
// fields: 0 width, 1 height, 2 format, 3 usage, 4 pool, 5 data, 6 pitch, 7 container, 8 msaa, 9 level/face
enum { S_W, S_H, S_FMT, S_USAGE, S_POOL, S_DATA, S_PITCH, S_CONT, S_MS, S_LEVEL, S_DIRTY, S_HOST, S_LOCKS, S_EVICT, S_NF };

// ---- surface data eviction ------------------------------------------------------------------------
// Real D3D keeps texture contents in VRAM, outside the 32-bit address space. Here a surface's bytes
// live in guest memory only while something holds a pointer to them (LockRect..UnlockRect, d3dx
// fills, UpdateSurface): the first pin allocates them (zeroed), the last unpin moves them to host
// memory (S_EVICT = slot + 1, S_DATA = 0), and the backend uploads from wherever they are.
#include <pthread.h>
static pthread_mutex_t ev_lk = PTHREAD_MUTEX_INITIALIZER;
static struct { void *p; uint32_t n; } *ev_tab; static uint32_t ev_cap, ev_free_head;   // free list through n
static uint64_t ev_bytes, ev_count;
static void level_layout(uint32_t fmt, uint32_t w, uint32_t h, uint32_t *pitch, uint32_t *size);
static void surf_restore_locked(uint32_t s) {
    uint32_t e = G32(OBJ_F(s, S_EVICT));
    if (!e) {
        if (!G32(OBJ_F(s, S_DATA))) {                // never written: allocate on first use
            uint32_t pitch, sz; level_layout(G32(OBJ_F(s, S_FMT)), G32(OBJ_F(s, S_W)), G32(OBJ_F(s, S_H)), &pitch, &sz);
            P32(OBJ_F(s, S_DATA), gmalloc(sz ? sz : 4));
        }
        return;
    }
    uint32_t n = ev_tab[e - 1].n, d = gmalloc(n ? n : 4);
    memcpy(MEM + d, ev_tab[e - 1].p, n);
    free(ev_tab[e - 1].p); ev_tab[e - 1].p = NULL; ev_tab[e - 1].n = ev_free_head; ev_free_head = e;
    ev_bytes -= n; ev_count--;
    P32(OBJ_F(s, S_DATA), d); P32(OBJ_F(s, S_EVICT), 0);
}
static uint32_t surf_pin(uint32_t s) {
    pthread_mutex_lock(&ev_lk);
    surf_restore_locked(s);
    P32(OBJ_F(s, S_LOCKS), G32(OBJ_F(s, S_LOCKS)) + 1);
    uint32_t d = G32(OBJ_F(s, S_DATA));
    pthread_mutex_unlock(&ev_lk);
    return d;
}
static void surf_evict_locked(uint32_t s);
static void surf_unpin(uint32_t s) {
    pthread_mutex_lock(&ev_lk);
    uint32_t l = G32(OBJ_F(s, S_LOCKS)); if (l) P32(OBJ_F(s, S_LOCKS), l - 1);
    if (l <= 1) surf_evict_locked(s);
    pthread_mutex_unlock(&ev_lk);
}
static void surf_evict_locked(uint32_t s) {
    uint32_t d = G32(OBJ_F(s, S_DATA)), n = d ? gsize(d) : 0;
    if (d && n >= 4096 && !G32(OBJ_F(s, S_LOCKS)) && !G32(OBJ_F(s, S_EVICT))) {
        uint32_t e = ev_free_head;
        if (e) ev_free_head = ev_tab[e - 1].n;
        else {
            if (ev_cap % 4096 == 0) ev_tab = realloc(ev_tab, sizeof *ev_tab * (ev_cap + 4096));
            e = ++ev_cap;
        }
        ev_tab[e - 1].p = malloc(n); ev_tab[e - 1].n = n;
        memcpy(ev_tab[e - 1].p, MEM + d, n);
        gfree(d); ev_bytes += n; ev_count++;
        P32(OBJ_F(s, S_DATA), 0); P32(OBJ_F(s, S_EVICT), e);
    }
}
// backend: the bytes of a surface wherever they live (NULL: never written); holds the residency lock
// until d3d_surf_end, so a concurrent pin cannot free the host copy mid-upload
const uint8_t *d3d_surf_begin(uint32_t s) {
    pthread_mutex_lock(&ev_lk);
    uint32_t e = G32(OBJ_F(s, S_EVICT)), d = G32(OBJ_F(s, S_DATA));
    return e ? (const uint8_t *)ev_tab[e - 1].p : d ? MEM + d : NULL;
}
void d3d_surf_end(void) { pthread_mutex_unlock(&ev_lk); }
static void surf_drop_evicted(uint32_t s) {          // free: discard a host copy
    pthread_mutex_lock(&ev_lk);
    uint32_t e = G32(OBJ_F(s, S_EVICT));
    if (e) { ev_bytes -= ev_tab[e - 1].n; ev_count--; free(ev_tab[e - 1].p); ev_tab[e - 1].p = NULL; ev_tab[e - 1].n = ev_free_head; ev_free_head = e; P32(OBJ_F(s, S_EVICT), 0); }
    pthread_mutex_unlock(&ev_lk);
}
static uint64_t d3d_surf_bytes, d3d_surf_live, d3d_buf_bytes, d3d_buf_live;   // accounting
static uint32_t new_surface(uint32_t dev, uint32_t w, uint32_t h, uint32_t fmt, uint32_t usage, uint32_t pool, uint32_t ms,
                            uint32_t container, uint32_t data, uint32_t pitch) {
    uint32_t s = newobj(vt_surf, K_SURF, dev, S_NF);
    uint32_t sz = 0;
    if (!data) { level_layout(fmt, w, h, &pitch, &sz); d3d_surf_bytes += sz; d3d_surf_live++; }   // bytes allocated on first pin
    P32(OBJ_F(s, S_W), w); P32(OBJ_F(s, S_H), h); P32(OBJ_F(s, S_FMT), fmt); P32(OBJ_F(s, S_USAGE), usage);
    P32(OBJ_F(s, S_POOL), pool); P32(OBJ_F(s, S_DATA), data); P32(OBJ_F(s, S_PITCH), pitch);
    P32(OBJ_F(s, S_CONT), container); P32(OBJ_F(s, S_MS), ms);
    d3d_backend_created(s);
    return s;
}
static void Surf_GetDesc(CPU *c) {
    uint32_t s = COM_THIS(c), d = ARG(c, 1);
    P32(d, G32(OBJ_F(s, S_FMT))); P32(d + 4, 1); P32(d + 8, G32(OBJ_F(s, S_USAGE))); P32(d + 12, G32(OBJ_F(s, S_POOL)));
    P32(d + 16, G32(OBJ_F(s, S_MS))); P32(d + 20, 0); P32(d + 24, G32(OBJ_F(s, S_W))); P32(d + 28, G32(OBJ_F(s, S_H)));
    RET(c, 0, 2);
}
static void Surf_LockRect(CPU *c) {
    uint32_t s = COM_THIS(c), lr = ARG(c, 1), rect = ARG(c, 2);
    uint32_t data = surf_pin(s), pitch = G32(OBJ_F(s, S_PITCH)), fmt = G32(OBJ_F(s, S_FMT));
    if (rect) {
        uint32_t x = G32(rect), y = G32(rect + 4); int blk = d3d_fmt_block(fmt);
        data += blk ? (y / 4) * pitch + (x / 4) * (uint32_t)blk : y * pitch + x * (uint32_t)d3d_fmt_bpp(fmt);
    }
    P32(lr, pitch); P32(lr + 4, data);
    RET(c, 0, 4);
}
static void Surf_UnlockRect(CPU *c) { surf_unpin(COM_THIS(c)); d3d_backend_dirty(COM_THIS(c)); RET(c, 0, 1); }
static void Surf_GetContainer(CPU *c) {
    uint32_t cont = G32(OBJ_F(COM_THIS(c), S_CONT));
    if (!cont) { P32(ARG(c, 2), 0); RET(c, E_NOINTERFACE, 3); return; }
    addref(cont); P32(ARG(c, 2), cont); RET(c, 0, 3);
}
static void Surf_GetDC(CPU *c) { P32(ARG(c, 1), 0); RET(c, D3DERR_INVALIDCALL, 2); }
static const Ov surf_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release}, {"GetDevice", Res_GetDevice},
    {"GetPriority", Res_GetPriority}, {"GetType", Res_GetType}, {"GetDesc", Surf_GetDesc}, {"LockRect", Surf_LockRect},
    {"UnlockRect", Surf_UnlockRect}, {"GetContainer", Surf_GetContainer}, {"GetDC", Surf_GetDC},
};

// ---- textures (2D, cube) -------------------------------------------------------------------------
// fields: 0 width, 1 height/edge, 2 levels, 3 format, 4 usage, 5 pool, 6 surfaces array ptr (levels*faces)
enum { T_W, T_H, T_LEVELS, T_FMT, T_USAGE, T_POOL, T_SURFS, T_FACES, T_LOD, T_DIRTY, T_HOST, T_NF };
static uint32_t new_texture(uint32_t dev, int kind, uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t fmt, uint32_t pool) {
    uint32_t faces = kind == K_CUBE ? 6 : 1;
    if (!levels) { levels = 1; uint32_t m = w > h ? w : h; while (m > 1) { m >>= 1; levels++; } }
    if (usage & 0x400) levels = 1;              // D3DUSAGE_AUTOGENMIPMAP exposes one level
    uint32_t t = newobj(kind == K_CUBE ? vt_cube : vt_tex, kind, dev, T_NF);
    P32(OBJ_F(t, T_W), w); P32(OBJ_F(t, T_H), h); P32(OBJ_F(t, T_LEVELS), levels); P32(OBJ_F(t, T_FMT), fmt);
    P32(OBJ_F(t, T_USAGE), usage); P32(OBJ_F(t, T_POOL), pool); P32(OBJ_F(t, T_FACES), faces);
    uint32_t arr = gmalloc(4 * levels * faces);
    for (uint32_t f = 0; f < faces; f++)
        for (uint32_t l = 0; l < levels; l++) {
            uint32_t lw = w >> l ? w >> l : 1, lh = h >> l ? h >> l : 1;
            uint32_t s = new_surface(dev, lw, lh, fmt, usage, pool, 0, t, 0, 0);
            P32(OBJ_F(s, S_LEVEL), l | (f << 16));
            P32(arr + 4 * (f * levels + l), s);
        }
    P32(OBJ_F(t, T_SURFS), arr);
    d3d_backend_created(t);
    return t;
}
static uint32_t tex_surf(uint32_t t, uint32_t face, uint32_t level) {
    uint32_t levels = G32(OBJ_F(t, T_LEVELS));
    if (level >= levels) return 0;
    return G32(G32(OBJ_F(t, T_SURFS)) + 4 * (face * levels + level));
}
static void Tex_GetLevelCount(CPU *c) { RET(c, G32(OBJ_F(COM_THIS(c), T_LEVELS)), 1); }
static void Tex_SetLOD(CPU *c) { uint32_t o = G32(OBJ_F(COM_THIS(c), T_LOD)); P32(OBJ_F(COM_THIS(c), T_LOD), ARG(c, 1)); RET(c, o, 2); }
static void Tex_GetLOD(CPU *c) { RET(c, G32(OBJ_F(COM_THIS(c), T_LOD)), 1); }
static void Tex_GetLevelDesc(CPU *c) {
    uint32_t s = tex_surf(COM_THIS(c), 0, ARG(c, 1));
    if (!s) { RET(c, D3DERR_INVALIDCALL, 3); return; }
    uint32_t d = ARG(c, 2);
    P32(d, G32(OBJ_F(s, S_FMT))); P32(d + 4, 1); P32(d + 8, G32(OBJ_F(s, S_USAGE))); P32(d + 12, G32(OBJ_F(s, S_POOL)));
    P32(d + 16, 0); P32(d + 20, 0); P32(d + 24, G32(OBJ_F(s, S_W))); P32(d + 28, G32(OBJ_F(s, S_H)));
    RET(c, 0, 3);
}
static void Tex_GetSurfaceLevel(CPU *c) {
    uint32_t s = tex_surf(COM_THIS(c), 0, ARG(c, 1));
    if (!s) { RET(c, D3DERR_INVALIDCALL, 3); return; }
    addref(s); P32(ARG(c, 2), s); RET(c, 0, 3);
}
static void lock_level(CPU *c, uint32_t s, uint32_t lr, uint32_t rect) {
    uint32_t data = surf_pin(s), pitch = G32(OBJ_F(s, S_PITCH)), fmt = G32(OBJ_F(s, S_FMT));
    if (rect) { uint32_t x = G32(rect), y = G32(rect + 4); int blk = d3d_fmt_block(fmt);
        data += blk ? (y / 4) * pitch + (x / 4) * (uint32_t)blk : y * pitch + x * (uint32_t)d3d_fmt_bpp(fmt); }
    P32(lr, pitch); P32(lr + 4, data);
    (void)c;
}
static void Tex_LockRect(CPU *c) {
    uint32_t s = tex_surf(COM_THIS(c), 0, ARG(c, 1));
    if (!s) { RET(c, D3DERR_INVALIDCALL, 5); return; }
    lock_level(c, s, ARG(c, 2), ARG(c, 3)); RET(c, 0, 5);
}
static void Tex_UnlockRect(CPU *c) { uint32_t s = tex_surf(COM_THIS(c), 0, ARG(c, 1)); if (s) { surf_unpin(s); d3d_backend_dirty(s); } RET(c, 0, 2); }
static void Cube_GetCubeMapSurface(CPU *c) {
    uint32_t s = tex_surf(COM_THIS(c), ARG(c, 1), ARG(c, 2));
    if (!s) { RET(c, D3DERR_INVALIDCALL, 4); return; }
    addref(s); P32(ARG(c, 3), s); RET(c, 0, 4);
}
static void Cube_LockRect(CPU *c) {
    uint32_t s = tex_surf(COM_THIS(c), ARG(c, 1), ARG(c, 2));
    if (!s) { RET(c, D3DERR_INVALIDCALL, 6); return; }
    lock_level(c, s, ARG(c, 3), ARG(c, 4)); RET(c, 0, 6);
}
static void Cube_UnlockRect(CPU *c) { uint32_t s = tex_surf(COM_THIS(c), ARG(c, 1), ARG(c, 2)); if (s) { surf_unpin(s); d3d_backend_dirty(s); } RET(c, 0, 3); }
static void Tex_GetAutoGen(CPU *c) { RET(c, 2 /* D3DTEXF_LINEAR */, 1); }
static const Ov tex_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release}, {"GetDevice", Res_GetDevice},
    {"GetPriority", Res_GetPriority}, {"GetType", Res_GetType}, {"SetLOD", Tex_SetLOD}, {"GetLOD", Tex_GetLOD},
    {"GetLevelCount", Tex_GetLevelCount}, {"GetAutoGenFilterType", Tex_GetAutoGen}, {"GetLevelDesc", Tex_GetLevelDesc},
    {"GetSurfaceLevel", Tex_GetSurfaceLevel}, {"LockRect", Tex_LockRect}, {"UnlockRect", Tex_UnlockRect},
};
static const Ov cube_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release}, {"GetDevice", Res_GetDevice},
    {"GetPriority", Res_GetPriority}, {"GetType", Res_GetType}, {"SetLOD", Tex_SetLOD}, {"GetLOD", Tex_GetLOD},
    {"GetLevelCount", Tex_GetLevelCount}, {"GetAutoGenFilterType", Tex_GetAutoGen}, {"GetLevelDesc", Tex_GetLevelDesc},
    {"GetCubeMapSurface", Cube_GetCubeMapSurface}, {"LockRect", Cube_LockRect}, {"UnlockRect", Cube_UnlockRect},
};

// ---- vertex / index buffers ------------------------------------------------------------------------
enum { B_LEN, B_USAGE, B_FMT, B_POOL, B_DATA, B_HOST, B_DIRTY, B_UPS, B_NF };   // HOST/DIRTY/UPS: backend-owned
static uint32_t new_buffer(uint32_t dev, int kind, uint32_t len, uint32_t usage, uint32_t fmt, uint32_t pool) {
    uint32_t b = newobj(kind == K_VB ? vt_vb : vt_ib, kind, dev, B_NF);
    P32(OBJ_F(b, B_LEN), len); P32(OBJ_F(b, B_USAGE), usage); P32(OBJ_F(b, B_FMT), fmt); P32(OBJ_F(b, B_POOL), pool);
    P32(OBJ_F(b, B_DATA), gmalloc(len ? len : 4)); d3d_buf_bytes += len; d3d_buf_live++;
    d3d_backend_created(b);
    return b;
}
static void Buf_Lock(CPU *c) { uint32_t b = COM_THIS(c); P32(ARG(c, 3), G32(OBJ_F(b, B_DATA)) + ARG(c, 1)); RET(c, 0, 5); }
static void Buf_Unlock(CPU *c) { d3d_backend_dirty(COM_THIS(c)); RET(c, 0, 1); }
static void Buf_GetDesc(CPU *c) {
    uint32_t b = COM_THIS(c), d = ARG(c, 1);
    int vb = OBJ_KIND(b) == K_VB;
    P32(d, vb ? 100 : G32(OBJ_F(b, B_FMT))); P32(d + 4, vb ? 6 : 7); P32(d + 8, G32(OBJ_F(b, B_USAGE)));
    P32(d + 12, G32(OBJ_F(b, B_POOL))); P32(d + 16, G32(OBJ_F(b, B_LEN))); if (vb) P32(d + 20, G32(OBJ_F(b, B_FMT)));
    RET(c, 0, 2);
}
static const Ov buf_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release}, {"GetDevice", Res_GetDevice},
    {"GetPriority", Res_GetPriority}, {"GetType", Res_GetType}, {"Lock", Buf_Lock}, {"Unlock", Buf_Unlock}, {"GetDesc", Buf_GetDesc},
};

// ---- shaders, declarations, queries, state blocks, swap chain --------------------------------------
static uint32_t copy_tokens(uint32_t src, uint32_t *ntok) {     // shader bytecode ends with 0x0000FFFF
    uint32_t n = 0; while (G32(src + 4 * n) != 0x0000FFFFu && n < (1u << 20)) n++;
    n++;
    uint32_t dst = gmalloc(4 * n); memcpy(MEM + dst, MEM + src, 4 * n);
    *ntok = n; return dst;
}
static void Shader_GetFunction(CPU *c) {
    uint32_t o = COM_THIS(c), n = G32(OBJ_F(o, 1)), buf = ARG(c, 1);
    if (buf) memcpy(MEM + buf, MEM + G32(OBJ_F(o, 0)), 4 * n);
    P32(ARG(c, 2), 4 * n); RET(c, 0, 3);
}
static const Ov shader_ov[] = {{"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
                               {"GetDevice", Res_GetDevice}, {"GetFunction", Shader_GetFunction}};
static void Decl_GetDeclaration(CPU *c) {
    uint32_t o = COM_THIS(c), n = G32(OBJ_F(o, 1)), buf = ARG(c, 1);
    if (buf) memcpy(MEM + buf, MEM + G32(OBJ_F(o, 0)), 8 * n);
    P32(ARG(c, 2), n); RET(c, 0, 3);
}
static const Ov decl_ov[] = {{"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
                             {"GetDevice", Res_GetDevice}, {"GetDeclaration", Decl_GetDeclaration}};
static void Query_GetType(CPU *c) { RET(c, G32(OBJ_F(COM_THIS(c), 0)), 1); }
static void Query_GetDataSize(CPU *c) { uint32_t t = G32(OBJ_F(COM_THIS(c), 0)); RET(c, t == 9 ? 4 : t == 8 ? 4 : 4, 1); }
static void Query_GetData(CPU *c) {
    uint32_t t = G32(OBJ_F(COM_THIS(c), 0)), out = ARG(c, 1), n = ARG(c, 2);
    if (out && n >= 4) P32(out, t == 9 ? 1000 /* occlusion: visible */ : 1 /* event: done */);
    RET(c, 0, 4);
}
static const Ov query_ov[] = {{"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
                              {"GetDevice", Res_GetDevice}, {"GetType", Query_GetType}, {"GetDataSize", Query_GetDataSize},
                              {"GetData", Query_GetData}};
static const Ov sb_ov[] = {{"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
                           {"GetDevice", Res_GetDevice}};

// ---- the device ------------------------------------------------------------------------------------
D3DState g_d3d;          // the one device's state (FNV creates a single device)

#include <pthread.h>
#define GRAVE_N 65536
static pthread_mutex_t grave_lk = PTHREAD_MUTEX_INITIALIZER;
static struct { uint32_t o; uint64_t frame; } grave[GRAVE_N];
static int ngrave;
static uint64_t grave_freed;
static void bury_locked(uint32_t o) {
    int k = (int)OBJ_KIND(o);
    if (k != K_TEX && k != K_CUBE && k != K_SURF && k != K_VB && k != K_IB) return;
    if (k == K_SURF && G32(OBJ_F(o, S_CONT))) return;           // owned by a live texture
    if (ngrave < GRAVE_N) { grave[ngrave].o = o; grave[ngrave].frame = g_d3d.frames; ngrave++; }
}
static void bury(uint32_t o) { pthread_mutex_lock(&grave_lk); bury_locked(o); pthread_mutex_unlock(&grave_lk); }
static int is_bound(uint32_t o) {
    for (int i = 0; i < 32; i++) if (g_d3d.tex[i] == o) return 1;
    for (int i = 0; i < 16; i++) if (g_d3d.stream[i] == o) return 1;
    for (int i = 0; i < 4; i++) if (g_d3d.rt[i] == o) return 1;
    return g_d3d.indices == o || g_d3d.ds == o || g_d3d.backbuffer == o;
}
static void free_obj(uint32_t o) {
    int k = (int)OBJ_KIND(o);
    if (k == K_TEX || k == K_CUBE) {
        uint32_t arr = G32(OBJ_F(o, T_SURFS)), n = G32(OBJ_F(o, T_LEVELS)) * G32(OBJ_F(o, T_FACES));
        for (uint32_t i = 0; arr && i < n; i++) {
            uint32_t s = G32(arr + 4 * i);
            if (!s) continue;
            P32(OBJ_F(s, S_CONT), 0);                            // the texture's reference on its levels
            uint32_t r = G32(s + 4); if (r) r--; P32(s + 4, r);
            if (!r) { d3d_backend_release(s); bury_locked(s); }    // a level the game still holds stays alive
        }
        if (arr) gfree(arr);
    } else if (k == K_SURF) {
        d3d_surf_live--;
        surf_drop_evicted(o);
        if (G32(OBJ_F(o, S_DATA))) { d3d_surf_bytes -= gsize(G32(OBJ_F(o, S_DATA))); gfree(G32(OBJ_F(o, S_DATA))); }
    } else if (k == K_VB || k == K_IB) {
        if (G32(OBJ_F(o, B_DATA))) { d3d_buf_bytes -= G32(OBJ_F(o, B_LEN)); d3d_buf_live--; gfree(G32(OBJ_F(o, B_DATA))); }
    }
    P32(o + 8, 0);                                                 // kind 0: a stale pointer can't pass for a resource
    gfree(o);
    grave_freed++;
}
static void reap(void) {                                           // called once per Present
    pthread_mutex_lock(&grave_lk);
    // compacting in place; free_obj may append texture levels, which this loop then keeps (too young)
    int w = 0;
    for (int i = 0; i < ngrave; i++) {
        uint32_t o = grave[i].o;
        if (G32(o + 4) != 0) continue;                               // resurrected by an AddRef: not ours
        if (grave[i].frame + 3 <= g_d3d.frames && !is_bound(o)) free_obj(o);
        else grave[w++] = grave[i];
    }
    ngrave = w;
    if (g_d3d.frames % 3000 == 0)
        fprintf(stderr, "[d3d] surfaces %llu live (%llu evicted to host: %llu MB), buffers %llu live / %llu MB, freed %llu objects, %d waiting\n",
                (unsigned long long)d3d_surf_live, (unsigned long long)ev_count, (unsigned long long)(ev_bytes >> 20),
                (unsigned long long)d3d_buf_live, (unsigned long long)(d3d_buf_bytes >> 20), (unsigned long long)grave_freed, ngrave);
    pthread_mutex_unlock(&grave_lk);
}

static void Swap_GetBackBuffer(CPU *c) { uint32_t s = g_d3d.backbuffer; addref(s); P32(ARG(c, 3), s); RET(c, 0, 4); }
static void Swap_GetPresentParameters(CPU *c) { memcpy(MEM + ARG(c, 1), g_d3d.pp, 56); RET(c, 0, 2); }
static void Swap_Present(CPU *c) { d3d_backend_present(&g_d3d); reap(); RET(c, 0, 6); }
static void Swap_GetDisplayMode(CPU *c) { uint32_t m = ARG(c, 1); P32(m, g_d3d.width); P32(m + 4, g_d3d.height); P32(m + 8, 60); P32(m + 12, 22); RET(c, 0, 2); }
static const Ov swap_ov[] = {{"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
                             {"Present", Swap_Present}, {"GetBackBuffer", Swap_GetBackBuffer}, {"GetDisplayMode", Swap_GetDisplayMode},
                             {"GetDevice", Res_GetDevice}, {"GetPresentParameters", Swap_GetPresentParameters}};

static void Dev_TestCooperativeLevel(CPU *c) { RET(c, 0, 1); }
static void Dev_GetAvailableTextureMem(CPU *c) { RET(c, 0x7FF00000u, 1); }
static void Dev_GetDirect3D(CPU *c) { addref(g_d3d.d3d); P32(ARG(c, 1), g_d3d.d3d); RET(c, 0, 2); }
static void Dev_GetDeviceCaps(CPU *c);
static void Dev_GetDisplayMode(CPU *c) { uint32_t m = ARG(c, 2); P32(m, g_d3d.width); P32(m + 4, g_d3d.height); P32(m + 8, 60); P32(m + 12, 22); RET(c, 0, 3); }
static void Dev_GetCreationParameters(CPU *c) { uint32_t p = ARG(c, 1); P32(p, 0); P32(p + 4, 1); P32(p + 8, g_d3d.hwnd); P32(p + 12, 0x40); RET(c, 0, 2); }
static void Dev_GetSwapChain(CPU *c) { addref(g_d3d.swapchain); P32(ARG(c, 2), g_d3d.swapchain); RET(c, 0, 3); }
static void Dev_GetNumberOfSwapChains(CPU *c) { RET(c, 1, 1); }
static void Dev_Reset(CPU *c) {
    uint32_t pp = ARG(c, 1);
    memcpy(g_d3d.pp, MEM + pp, 56);
    if (G32(pp)) g_d3d.width = G32(pp); if (G32(pp + 4)) g_d3d.height = G32(pp + 4);
    fprintf(stderr, "[d3d9] Reset %ux%u\n", g_d3d.width, g_d3d.height);
    d3d_backend_resize(&g_d3d);
    RET(c, 0, 2);
}
static void Dev_Present(CPU *c) { d3d_backend_present(&g_d3d); reap(); RET(c, 0, 5); }
static void Dev_GetBackBuffer(CPU *c) { uint32_t s = g_d3d.backbuffer; addref(s); P32(ARG(c, 4), s); RET(c, 0, 5); }
static void Dev_GetRasterStatus(CPU *c) { memset(MEM + ARG(c, 2), 0, 8); RET(c, 0, 3); }
static void Dev_CreateTexture(CPU *c) {
    uint32_t t = new_texture(COM_THIS(c), K_TEX, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), ARG(c, 5), ARG(c, 6));
    if (trace_d3d()) fprintf(stderr, "[d3d9] CreateTexture %ux%u lv%u fmt %#x usage %#x -> %#x\n", ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 5), ARG(c, 4), t);
    P32(ARG(c, 7), t); RET(c, 0, 9);
}
static void Dev_CreateVolumeTexture(CPU *c) {
    // rare in FNV; a 2D stand-in with depth folded into height keeps the object usable
    uint32_t t = new_texture(COM_THIS(c), K_TEX, ARG(c, 1), ARG(c, 2) * ARG(c, 3), ARG(c, 4), ARG(c, 5), ARG(c, 6), ARG(c, 7));
    P32(ARG(c, 8), t); RET(c, 0, 10);
}
static void Dev_CreateCubeTexture(CPU *c) {
    uint32_t t = new_texture(COM_THIS(c), K_CUBE, ARG(c, 1), ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), ARG(c, 5));
    P32(ARG(c, 6), t); RET(c, 0, 8);
}
static void Dev_CreateVertexBuffer(CPU *c) { P32(ARG(c, 5), new_buffer(COM_THIS(c), K_VB, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4))); RET(c, 0, 7); }
static void Dev_CreateIndexBuffer(CPU *c) { P32(ARG(c, 5), new_buffer(COM_THIS(c), K_IB, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4))); RET(c, 0, 7); }
static void Dev_CreateRenderTarget(CPU *c) {
    uint32_t s = new_surface(COM_THIS(c), ARG(c, 1), ARG(c, 2), ARG(c, 3), 1 /* RENDERTARGET */, 0, ARG(c, 4), 0, 0, 0);
    P32(ARG(c, 7), s); RET(c, 0, 9);
}
static void Dev_CreateDepthStencilSurface(CPU *c) {
    uint32_t s = new_surface(COM_THIS(c), ARG(c, 1), ARG(c, 2), ARG(c, 3), 2 /* DEPTHSTENCIL */, 0, ARG(c, 4), 0, 0, 0);
    P32(ARG(c, 7), s); RET(c, 0, 9);
}
static void Dev_CreateOffscreenPlainSurface(CPU *c) {
    uint32_t s = new_surface(COM_THIS(c), ARG(c, 1), ARG(c, 2), ARG(c, 3), 0, ARG(c, 4), 0, 0, 0, 0);
    P32(ARG(c, 5), s); RET(c, 0, 7);
}
static void Dev_SetRenderTarget(CPU *c) {
    uint32_t i = ARG(c, 1), s = ARG(c, 2);
    if (i < 4) { if (s) addref(s); g_d3d.rt[i] = s; }
    if (i == 0 && s) { g_d3d.viewport[0] = 0; g_d3d.viewport[1] = 0; g_d3d.viewport[2] = G32(OBJ_F(s, S_W)); g_d3d.viewport[3] = G32(OBJ_F(s, S_H)); }
    RET(c, 0, 3);
}
static void Dev_GetRenderTarget(CPU *c) { uint32_t i = ARG(c, 1), s = i < 4 ? g_d3d.rt[i] : 0; addref(s); P32(ARG(c, 2), s); RET(c, s ? 0 : D3DERR_NOTAVAILABLE, 3); }
static void Dev_SetDepthStencilSurface(CPU *c) { g_d3d.ds = ARG(c, 1); addref(g_d3d.ds); RET(c, 0, 2); }
static void Dev_GetDepthStencilSurface(CPU *c) { addref(g_d3d.ds); P32(ARG(c, 1), g_d3d.ds); RET(c, g_d3d.ds ? 0 : D3DERR_NOTAVAILABLE, 2); }
static void Dev_BeginScene(CPU *c) { RET(c, 0, 1); }
static void Dev_EndScene(CPU *c) { RET(c, 0, 1); }
static void Dev_Clear(CPU *c) {
    float z; uint32_t zb = ARG(c, 5); memcpy(&z, &zb, 4);
    d3d_backend_clear(&g_d3d, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), z, ARG(c, 6));
    RET(c, 0, 7);
}
static void Dev_SetTransform(CPU *c) { uint32_t s = ARG(c, 1); if (s < 512) memcpy(g_d3d.transform[s], MEM + ARG(c, 2), 64); RET(c, 0, 3); }
static void Dev_GetTransform(CPU *c) { uint32_t s = ARG(c, 1); if (s < 512) memcpy(MEM + ARG(c, 2), g_d3d.transform[s], 64); RET(c, 0, 3); }
static void Dev_SetViewport(CPU *c) { memcpy(g_d3d.viewport, MEM + ARG(c, 1), 24); RET(c, 0, 2); }
static void Dev_GetViewport(CPU *c) { memcpy(MEM + ARG(c, 1), g_d3d.viewport, 24); RET(c, 0, 2); }
static void Dev_SetRenderState(CPU *c) { uint32_t s = ARG(c, 1); if (s < 256) g_d3d.rs[s] = ARG(c, 2); RET(c, 0, 3); }
static void Dev_GetRenderState(CPU *c) { uint32_t s = ARG(c, 1); P32(ARG(c, 2), s < 256 ? g_d3d.rs[s] : 0); RET(c, 0, 3); }
static void Dev_CreateStateBlock(CPU *c) { P32(ARG(c, 2), newobj(vt_sb, K_SB, COM_THIS(c), 1)); RET(c, 0, 3); }
static void Dev_EndStateBlock(CPU *c) { P32(ARG(c, 1), newobj(vt_sb, K_SB, COM_THIS(c), 1)); RET(c, 0, 2); }
static void Dev_SetClipStatus(CPU *c) { RET(c, 0, 2); }
static void Dev_GetTexture(CPU *c) { uint32_t s = ARG(c, 1), t = s < 32 ? g_d3d.tex[s] : 0; addref(t); P32(ARG(c, 2), t); RET(c, 0, 3); }
static void Dev_SetTexture(CPU *c) { uint32_t s = ARG(c, 1); if (s >= 257) s = s - 257 + 16; if (s < 32) g_d3d.tex[s] = ARG(c, 2); RET(c, 0, 3); }
static void Dev_GetTextureStageState(CPU *c) { uint32_t s = ARG(c, 1), t = ARG(c, 2); P32(ARG(c, 3), s < 8 && t < 33 ? g_d3d.tss[s][t] : 0); RET(c, 0, 4); }
static void Dev_SetTextureStageState(CPU *c) { uint32_t s = ARG(c, 1), t = ARG(c, 2); if (s < 8 && t < 33) g_d3d.tss[s][t] = ARG(c, 3); RET(c, 0, 4); }
static void Dev_GetSamplerState(CPU *c) { uint32_t s = ARG(c, 1), t = ARG(c, 2); if (s >= 257) s = s - 257 + 16; P32(ARG(c, 3), s < 32 && t < 14 ? g_d3d.ss[s][t] : 0); RET(c, 0, 4); }
static void Dev_SetSamplerState(CPU *c) { uint32_t s = ARG(c, 1), t = ARG(c, 2); if (s >= 257) s = s - 257 + 16; if (s < 32 && t < 14) g_d3d.ss[s][t] = ARG(c, 3); RET(c, 0, 4); }
static void Dev_ValidateDevice(CPU *c) { P32(ARG(c, 1), 1); RET(c, 0, 2); }
static void Dev_SetScissorRect(CPU *c) { memcpy(g_d3d.scissor, MEM + ARG(c, 1), 16); RET(c, 0, 2); }
static void Dev_GetScissorRect(CPU *c) { memcpy(MEM + ARG(c, 1), g_d3d.scissor, 16); RET(c, 0, 2); }
static void Dev_GetSoftwareVertexProcessing(CPU *c) { RET(c, 0, 1); }
static void Dev_GetNPatchMode(CPU *c) { RET(c, 0, 1); }
static void Dev_DrawPrimitive(CPU *c) { d3d_backend_draw(&g_d3d, ARG(c, 1), ARG(c, 2), ARG(c, 3), 0, 0, 0, 0); RET(c, 0, 4); }
static void Dev_DrawIndexedPrimitive(CPU *c) { d3d_backend_draw(&g_d3d, ARG(c, 1), ARG(c, 5), ARG(c, 6), 1, (int32_t)ARG(c, 2), ARG(c, 3), ARG(c, 4)); RET(c, 0, 7); }
static void Dev_DrawPrimitiveUP(CPU *c) { d3d_backend_draw_up(&g_d3d, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), 0, 0, 0, 0); g_d3d.stream[0] = 0; RET(c, 0, 5); }
static void Dev_DrawIndexedPrimitiveUP(CPU *c) {
    d3d_backend_draw_up(&g_d3d, ARG(c, 1), ARG(c, 4), ARG(c, 7), ARG(c, 8), ARG(c, 5), ARG(c, 6), ARG(c, 2), ARG(c, 3));
    g_d3d.stream[0] = 0; g_d3d.indices = 0; RET(c, 0, 9);
}
static void Dev_CreateVertexDeclaration(CPU *c) {
    uint32_t src = ARG(c, 1), n = 0;
    while ((G32(src + 8 * n) & 0xFFFF) != 0xFF) n++;
    n++;
    uint32_t o = newobj(vt_decl, K_DECL, COM_THIS(c), 2), copy = gmalloc(8 * n);
    memcpy(MEM + copy, MEM + src, 8 * n);
    P32(OBJ_F(o, 0), copy); P32(OBJ_F(o, 1), n);
    P32(ARG(c, 2), o); RET(c, 0, 3);
}
static void Dev_SetVertexDeclaration(CPU *c) { g_d3d.decl = ARG(c, 1); RET(c, 0, 2); }
static void Dev_GetVertexDeclaration(CPU *c) { addref(g_d3d.decl); P32(ARG(c, 1), g_d3d.decl); RET(c, 0, 2); }
static void Dev_SetFVF(CPU *c) { g_d3d.fvf = ARG(c, 1); g_d3d.decl = 0; RET(c, 0, 2); }
static void Dev_GetFVF(CPU *c) { P32(ARG(c, 1), g_d3d.fvf); RET(c, 0, 2); }
static void Dev_CreateShader(CPU *c, uint32_t vt, int kind) {
    uint32_t n, code = copy_tokens(ARG(c, 1), &n);
    uint32_t o = newobj(vt, kind, COM_THIS(c), 3);       // code, ntok, host index
    P32(OBJ_F(o, 0), code); P32(OBJ_F(o, 1), n);
    d3d_backend_created(o);
    P32(ARG(c, 2), o); RET(c, 0, 3);
}
static void Dev_CreateVertexShader(CPU *c) { Dev_CreateShader(c, vt_vs, K_VS); }
static void Dev_CreatePixelShader(CPU *c) { Dev_CreateShader(c, vt_ps, K_PS); }
static void Dev_SetVertexShader(CPU *c) { g_d3d.vs = ARG(c, 1); RET(c, 0, 2); }
static void Dev_GetVertexShader(CPU *c) { addref(g_d3d.vs); P32(ARG(c, 1), g_d3d.vs); RET(c, 0, 2); }
static void Dev_SetPixelShader(CPU *c) { g_d3d.ps = ARG(c, 1); RET(c, 0, 2); }
static void Dev_GetPixelShader(CPU *c) { addref(g_d3d.ps); P32(ARG(c, 1), g_d3d.ps); RET(c, 0, 2); }
static void consts(float (*dst)[4], uint32_t cap, CPU *c, int set) {
    uint32_t start = ARG(c, 1), p = ARG(c, 2), n = ARG(c, 3);
    if (start + n > cap) n = start < cap ? cap - start : 0;
    if (set) memcpy(dst[start], MEM + p, 16 * n); else memcpy(MEM + p, dst[start], 16 * n);
}
static void Dev_SetVertexShaderConstantF(CPU *c) { consts(g_d3d.vsc, 256, c, 1); g_d3d.vsc_dirty = 1; RET(c, 0, 4); }
static void Dev_GetVertexShaderConstantF(CPU *c) { consts(g_d3d.vsc, 256, c, 0); RET(c, 0, 4); }
static void Dev_SetPixelShaderConstantF(CPU *c) { consts(g_d3d.psc, 224, c, 1); g_d3d.psc_dirty = 1; RET(c, 0, 4); }
static void Dev_GetPixelShaderConstantF(CPU *c) { consts(g_d3d.psc, 224, c, 0); RET(c, 0, 4); }
static void Dev_SetVertexShaderConstantB(CPU *c) { uint32_t s = ARG(c, 1), n = ARG(c, 3); for (uint32_t i = 0; i < n && s + i < 16; i++) g_d3d.vsb[s + i] = G32(ARG(c, 2) + 4 * i); RET(c, 0, 4); }
static void Dev_SetPixelShaderConstantB(CPU *c) { uint32_t s = ARG(c, 1), n = ARG(c, 3); for (uint32_t i = 0; i < n && s + i < 16; i++) g_d3d.psb[s + i] = G32(ARG(c, 2) + 4 * i); RET(c, 0, 4); }
static void Dev_SetVertexShaderConstantI(CPU *c) { uint32_t s = ARG(c, 1), n = ARG(c, 3); if (s + n <= 16) memcpy(g_d3d.vsi[s], MEM + ARG(c, 2), 16 * n); RET(c, 0, 4); }
static void Dev_SetPixelShaderConstantI(CPU *c) { uint32_t s = ARG(c, 1), n = ARG(c, 3); if (s + n <= 16) memcpy(g_d3d.psi[s], MEM + ARG(c, 2), 16 * n); RET(c, 0, 4); }
static void Dev_SetStreamSource(CPU *c) { uint32_t s = ARG(c, 1); if (s < 16) { g_d3d.stream[s] = ARG(c, 2); g_d3d.stream_off[s] = ARG(c, 3); g_d3d.stream_stride[s] = ARG(c, 4); } RET(c, 0, 5); }
static void Dev_GetStreamSource(CPU *c) {
    uint32_t s = ARG(c, 1);
    if (s < 16) { addref(g_d3d.stream[s]); P32(ARG(c, 2), g_d3d.stream[s]); P32(ARG(c, 3), g_d3d.stream_off[s]); P32(ARG(c, 4), g_d3d.stream_stride[s]); }
    RET(c, 0, 5);
}
static void Dev_SetStreamSourceFreq(CPU *c) { uint32_t s = ARG(c, 1); if (s < 16) g_d3d.stream_freq[s] = ARG(c, 2); RET(c, 0, 3); }
static void Dev_GetStreamSourceFreq(CPU *c) { uint32_t s = ARG(c, 1); P32(ARG(c, 2), s < 16 ? g_d3d.stream_freq[s] : 1); RET(c, 0, 3); }
static void Dev_SetIndices(CPU *c) { g_d3d.indices = ARG(c, 1); RET(c, 0, 2); }
static void Dev_GetIndices(CPU *c) { addref(g_d3d.indices); P32(ARG(c, 1), g_d3d.indices); RET(c, 0, 2); }
static void Dev_CreateQuery(CPU *c) {
    uint32_t type = ARG(c, 1), out = ARG(c, 2);
    if (!out) { RET(c, (type == 8 || type == 9) ? 0 : D3DERR_NOTAVAILABLE, 3); return; }   // support probe
    uint32_t q = newobj(vt_query, K_QUERY, COM_THIS(c), 1); P32(OBJ_F(q, 0), type);
    P32(out, q); RET(c, 0, 3);
}
static void Dev_StretchRect(CPU *c) { d3d_backend_stretch(&g_d3d, ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), ARG(c, 5)); RET(c, 0, 6); }
static void Dev_UpdateSurface(CPU *c) {
    uint32_t src = ARG(c, 1), dst = ARG(c, 3);
    uint32_t n = G32(OBJ_F(src, S_PITCH)) * G32(OBJ_F(src, S_H)), m = G32(OBJ_F(dst, S_PITCH)) * G32(OBJ_F(dst, S_H));
    if (!ARG(c, 2) && !ARG(c, 4) && n == m) {
        uint32_t a = surf_pin(src), b = surf_pin(dst);
        memcpy(MEM + b, MEM + a, n);
        surf_unpin(src); surf_unpin(dst); d3d_backend_dirty(dst);
    }
    RET(c, 0, 5);
}
static void Dev_UpdateTexture(CPU *c) {
    uint32_t src = ARG(c, 1), dst = ARG(c, 2);
    uint32_t lv = G32(OBJ_F(src, T_LEVELS)) < G32(OBJ_F(dst, T_LEVELS)) ? G32(OBJ_F(src, T_LEVELS)) : G32(OBJ_F(dst, T_LEVELS));
    for (uint32_t f = 0; f < G32(OBJ_F(src, T_FACES)); f++)
        for (uint32_t l = 0; l < lv; l++) {
            uint32_t a = tex_surf(src, f, l), b = tex_surf(dst, f, l);
            uint32_t n = G32(OBJ_F(a, S_PITCH)) * G32(OBJ_F(a, S_H)), m = G32(OBJ_F(b, S_PITCH)) * G32(OBJ_F(b, S_H));
            if (n == m) {
                uint32_t pa = surf_pin(a), pb = surf_pin(b);
                memcpy(MEM + pb, MEM + pa, n);
                surf_unpin(a); surf_unpin(b); d3d_backend_dirty(b);
            }
        }
    RET(c, 0, 3);
}
static void Dev_GetRenderTargetData(CPU *c) { d3d_backend_readback(&g_d3d, ARG(c, 1), ARG(c, 2)); RET(c, 0, 3); }
static void Dev_ColorFill(CPU *c) { d3d_backend_colorfill(&g_d3d, ARG(c, 1), ARG(c, 2), ARG(c, 3)); RET(c, 0, 4); }
static void Dev_SetDialogBoxMode(CPU *c) { RET(c, 0, 2); }
static void Dev_SetGammaRamp(CPU *c) { RET(c, 0, 4); }
static void Dev_GetGammaRamp(CPU *c) { uint32_t r = ARG(c, 2); for (int i = 0; i < 256; i++) { uint16_t v = (uint16_t)(i * 257); for (int k = 0; k < 3; k++) memcpy(MEM + r + 512 * k + 2 * i, &v, 2); } RET(c, 0, 3); }

static const Ov dev_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
    {"TestCooperativeLevel", Dev_TestCooperativeLevel}, {"GetAvailableTextureMem", Dev_GetAvailableTextureMem},
    {"GetDirect3D", Dev_GetDirect3D}, {"GetDeviceCaps", Dev_GetDeviceCaps}, {"GetDisplayMode", Dev_GetDisplayMode},
    {"GetCreationParameters", Dev_GetCreationParameters}, {"GetSwapChain", Dev_GetSwapChain},
    {"GetNumberOfSwapChains", Dev_GetNumberOfSwapChains}, {"Reset", Dev_Reset}, {"Present", Dev_Present},
    {"GetBackBuffer", Dev_GetBackBuffer}, {"GetRasterStatus", Dev_GetRasterStatus}, {"SetDialogBoxMode", Dev_SetDialogBoxMode},
    {"SetGammaRamp", Dev_SetGammaRamp}, {"GetGammaRamp", Dev_GetGammaRamp},
    {"CreateTexture", Dev_CreateTexture}, {"CreateVolumeTexture", Dev_CreateVolumeTexture}, {"CreateCubeTexture", Dev_CreateCubeTexture},
    {"CreateVertexBuffer", Dev_CreateVertexBuffer}, {"CreateIndexBuffer", Dev_CreateIndexBuffer},
    {"CreateRenderTarget", Dev_CreateRenderTarget}, {"CreateDepthStencilSurface", Dev_CreateDepthStencilSurface},
    {"UpdateSurface", Dev_UpdateSurface}, {"UpdateTexture", Dev_UpdateTexture}, {"GetRenderTargetData", Dev_GetRenderTargetData},
    {"StretchRect", Dev_StretchRect}, {"ColorFill", Dev_ColorFill}, {"CreateOffscreenPlainSurface", Dev_CreateOffscreenPlainSurface},
    {"SetRenderTarget", Dev_SetRenderTarget}, {"GetRenderTarget", Dev_GetRenderTarget},
    {"SetDepthStencilSurface", Dev_SetDepthStencilSurface}, {"GetDepthStencilSurface", Dev_GetDepthStencilSurface},
    {"BeginScene", Dev_BeginScene}, {"EndScene", Dev_EndScene}, {"Clear", Dev_Clear},
    {"SetTransform", Dev_SetTransform}, {"GetTransform", Dev_GetTransform},
    {"SetViewport", Dev_SetViewport}, {"GetViewport", Dev_GetViewport},
    {"SetRenderState", Dev_SetRenderState}, {"GetRenderState", Dev_GetRenderState},
    {"CreateStateBlock", Dev_CreateStateBlock}, {"EndStateBlock", Dev_EndStateBlock}, {"SetClipStatus", Dev_SetClipStatus},
    {"GetTexture", Dev_GetTexture}, {"SetTexture", Dev_SetTexture},
    {"GetTextureStageState", Dev_GetTextureStageState}, {"SetTextureStageState", Dev_SetTextureStageState},
    {"GetSamplerState", Dev_GetSamplerState}, {"SetSamplerState", Dev_SetSamplerState}, {"ValidateDevice", Dev_ValidateDevice},
    {"SetScissorRect", Dev_SetScissorRect}, {"GetScissorRect", Dev_GetScissorRect},
    {"GetSoftwareVertexProcessing", Dev_GetSoftwareVertexProcessing}, {"GetNPatchMode", Dev_GetNPatchMode},
    {"DrawPrimitive", Dev_DrawPrimitive}, {"DrawIndexedPrimitive", Dev_DrawIndexedPrimitive},
    {"DrawPrimitiveUP", Dev_DrawPrimitiveUP}, {"DrawIndexedPrimitiveUP", Dev_DrawIndexedPrimitiveUP},
    {"CreateVertexDeclaration", Dev_CreateVertexDeclaration}, {"SetVertexDeclaration", Dev_SetVertexDeclaration},
    {"GetVertexDeclaration", Dev_GetVertexDeclaration}, {"SetFVF", Dev_SetFVF}, {"GetFVF", Dev_GetFVF},
    {"CreateVertexShader", Dev_CreateVertexShader}, {"SetVertexShader", Dev_SetVertexShader}, {"GetVertexShader", Dev_GetVertexShader},
    {"SetVertexShaderConstantF", Dev_SetVertexShaderConstantF}, {"GetVertexShaderConstantF", Dev_GetVertexShaderConstantF},
    {"SetVertexShaderConstantI", Dev_SetVertexShaderConstantI}, {"SetVertexShaderConstantB", Dev_SetVertexShaderConstantB},
    {"SetStreamSource", Dev_SetStreamSource}, {"GetStreamSource", Dev_GetStreamSource},
    {"SetStreamSourceFreq", Dev_SetStreamSourceFreq}, {"GetStreamSourceFreq", Dev_GetStreamSourceFreq},
    {"SetIndices", Dev_SetIndices}, {"GetIndices", Dev_GetIndices},
    {"CreatePixelShader", Dev_CreatePixelShader}, {"SetPixelShader", Dev_SetPixelShader}, {"GetPixelShader", Dev_GetPixelShader},
    {"SetPixelShaderConstantF", Dev_SetPixelShaderConstantF}, {"GetPixelShaderConstantF", Dev_GetPixelShaderConstantF},
    {"SetPixelShaderConstantI", Dev_SetPixelShaderConstantI}, {"SetPixelShaderConstantB", Dev_SetPixelShaderConstantB},
    {"CreateQuery", Dev_CreateQuery},
};

// ---- IDirect3D9 ----------------------------------------------------------------------------------
// TODO(M3): enumerate the real displays through CoreGraphics instead of a fixed list
static const struct { uint32_t w, h; } modes[] = {
    {640, 480}, {800, 600}, {1024, 768}, {1152, 864}, {1280, 720}, {1280, 800}, {1280, 960}, {1280, 1024},
    {1366, 768}, {1440, 900}, {1600, 900}, {1600, 1200}, {1680, 1050}, {1920, 1080}, {1920, 1200},
    {2560, 1440}, {2560, 1600}, {3024, 1964}, {3456, 1944}, {3456, 2234}, {3840, 2160}};
#define NMODES (sizeof modes / sizeof *modes)

static void D3D_GetAdapterCount(CPU *c) { RET(c, 1, 1); }
static void D3D_GetAdapterIdentifier(CPU *c) {
    uint32_t p = ARG(c, 3);
    memset(MEM + p, 0, 1100);
    strcpy((char *)MEM + p, "nvd3dum.dll");                  // Driver[512]
    strcpy((char *)MEM + p + 512, "NVIDIA GeForce GTX 580");  // Description[512]
    strcpy((char *)MEM + p + 1024, "\\\\.\\DISPLAY1");         // DeviceName[32]
    P32(p + 1056, 0x0008000F); P32(p + 1060, 0x000D0C4A);     // DriverVersion (8.17.12.6658)
    P32(p + 1064, 0x10DE); P32(p + 1068, 0x1080); P32(p + 1072, 0); P32(p + 1076, 0xA1);   // vendor, device, subsys, rev
    P32(p + 1080, 0xD7B71E3E); P32(p + 1084, 0x11CF5AE6); P32(p + 1088, 0x0B0A8160); P32(p + 1092, 0x35C2C9A0); // DeviceIdentifier
    P32(p + 1096, 1);                                         // WHQLLevel
    RET(c, 0, 4);
}
static void D3D_GetAdapterModeCount(CPU *c) { RET(c, (uint32_t)NMODES, 3); }
static void D3D_EnumAdapterModes(CPU *c) {
    uint32_t i = ARG(c, 3), m = ARG(c, 4);
    if (i >= NMODES) { RET(c, D3DERR_INVALIDCALL, 5); return; }
    P32(m, modes[i].w); P32(m + 4, modes[i].h); P32(m + 8, 60); P32(m + 12, ARG(c, 2) ? ARG(c, 2) : 22);
    RET(c, 0, 5);
}
static void D3D_GetAdapterDisplayMode(CPU *c) { uint32_t m = ARG(c, 2); P32(m, 1920); P32(m + 4, 1080); P32(m + 8, 60); P32(m + 12, 22); RET(c, 0, 3); }
static void D3D_CheckDeviceMultiSampleType(CPU *c) { if (ARG(c, 6)) P32(ARG(c, 6), 1); RET(c, ARG(c, 5) <= 8 ? 0 : D3DERR_NOTAVAILABLE, 7); }
static void D3D_GetAdapterMonitor(CPU *c) { RET(c, 0x00070001, 2); }

static void fill_caps(uint32_t p) {
    memset(MEM + p, 0, 304);
    uint32_t *f = (uint32_t *)(void *)(MEM + p);
    f[0] = 1; f[2] = 0x20000; f[3] = 0xE0000000u; f[4] = 0x3A0; f[5] = 0x8000000F;
    f[6] = 1; f[7] = 0x001BBEF0; f[8] = 0x2FCEF2; f[9] = 0x7732191; f[10] = 0xFF; f[11] = 0x3FFF; f[12] = 0x3FFF;
    f[13] = 0xFF; f[14] = 0x42108; f[15] = 0x1EC45; f[16] = 0x3030700; f[17] = 0x3030300; f[18] = 0x3030300;
    f[19] = 0x3F; f[20] = 0x3F; f[21] = 0x1F;
    f[22] = 8192; f[23] = 8192; f[24] = 2048; f[25] = 8192; f[26] = 8192; f[27] = 16;
    float big = 1e10f; memcpy(&f[28], &big, 4);
    float gb = -1e8f, gbp = 1e8f; memcpy(&f[29], &gb, 4); memcpy(&f[30], &gb, 4); memcpy(&f[31], &gbp, 4); memcpy(&f[32], &gbp, 4);
    f[34] = 0x1FF; f[35] = 0x180008; f[36] = 0x3FEFFFF; f[37] = 8; f[38] = 8; f[39] = 0x17B;
    f[40] = 8; f[41] = 8; f[42] = 4; f[43] = 0;
    float ps = 8192.0f; memcpy(&f[44], &ps, 4);
    f[45] = 0xFFFFF; f[46] = 0xFFFFF; f[47] = 16; f[48] = 255;
    f[49] = 0xFFFE0300u;         // VertexShaderVersion 3.0
    f[50] = 256;                 // MaxVertexShaderConst
    f[51] = 0xFFFF0300u;         // PixelShaderVersion 3.0
    float pmax = 3.4e38f; memcpy(&f[52], &pmax, 4);
    f[53] = 0x351; f[56] = 0; f[57] = 0; f[58] = 1;
    f[59] = 0x30F;               // DeclTypes
    f[60] = 4;                   // NumSimultaneousRTs
    f[61] = 0x3000300;
    f[62] = 1; f[63] = 24; f[64] = 32; f[65] = 4;                  // VS20Caps
    f[66] = 0x1F; f[67] = 24; f[68] = 32; f[69] = 4; f[70] = 512;  // PS20Caps
    f[71] = 0x3000300; f[72] = 65535; f[73] = 65535; f[74] = 32768; f[75] = 32768;
}
static void D3D_GetDeviceCaps(CPU *c) { fill_caps(ARG(c, 3)); RET(c, 0, 4); }
static void Dev_GetDeviceCaps(CPU *c) { fill_caps(ARG(c, 1)); RET(c, 0, 2); }

static void make_vtables(void) {
    if (vt_dev) return;
    vt_surf = VT(IDirect3DSurface9, surf_ov);
    vt_tex = VT(IDirect3DTexture9, tex_ov);
    vt_cube = VT(IDirect3DCubeTexture9, cube_ov);
    vt_vb = VT(IDirect3DVertexBuffer9, buf_ov);
    vt_ib = VT(IDirect3DIndexBuffer9, buf_ov);
    vt_vs = VT(IDirect3DVertexShader9, shader_ov);
    vt_ps = VT(IDirect3DPixelShader9, shader_ov);
    vt_decl = VT(IDirect3DVertexDeclaration9, decl_ov);
    vt_query = VT(IDirect3DQuery9, query_ov);
    vt_sb = VT(IDirect3DStateBlock9, sb_ov);
    vt_swap = VT(IDirect3DSwapChain9, swap_ov);
    vt_dev = VT(IDirect3DDevice9, dev_ov);
}

static void D3D_CreateDevice(CPU *c) {
    make_vtables();
    uint32_t pp = ARG(c, 5);
    memcpy(g_d3d.pp, MEM + pp, 56);
    g_d3d.width = G32(pp) ? G32(pp) : 1280; g_d3d.height = G32(pp + 4) ? G32(pp + 4) : 720;
    g_d3d.hwnd = ARG(c, 3); g_d3d.d3d = COM_THIS(c);
    uint32_t dev = newobj(vt_dev, 0, 0, 0);
    P32(dev + 12, dev);
    the_device = dev;
    g_d3d.backbuffer = new_surface(dev, g_d3d.width, g_d3d.height, G32(pp + 8) ? G32(pp + 8) : 21, 1, 0, G32(pp + 16), 0, 0, 0);
    g_d3d.swapchain = newobj(vt_swap, K_SWAP, dev, 0);
    if (G32(pp + 40)) g_d3d.ds = new_surface(dev, g_d3d.width, g_d3d.height, G32(pp + 44), 2, 0, G32(pp + 16), 0, 0, 0);  // auto depth
    g_d3d.rt[0] = g_d3d.backbuffer;
    g_d3d.viewport[2] = g_d3d.width; g_d3d.viewport[3] = g_d3d.height; { float one = 1.0f; memcpy(&g_d3d.viewport[5], &one, 4); }
    for (int s = 0; s < 16; s++) g_d3d.stream_freq[s] = 1;
    fprintf(stderr, "[d3d9] CreateDevice %ux%u fmt %u windowed=%u msaa=%u -> %#x\n", g_d3d.width, g_d3d.height, G32(pp + 8), G32(pp + 32), G32(pp + 16), dev);
    d3d_backend_init(&g_d3d);
    P32(ARG(c, 6), dev);
    RET(c, 0, 7);
}

static const Ov d3d_ov[] = {
    {"QueryInterface", Unk_QueryInterface}, {"AddRef", Unk_AddRef}, {"Release", Unk_Release},
    {"GetAdapterCount", D3D_GetAdapterCount}, {"GetAdapterIdentifier", D3D_GetAdapterIdentifier},
    {"GetAdapterModeCount", D3D_GetAdapterModeCount}, {"EnumAdapterModes", D3D_EnumAdapterModes},
    {"GetAdapterDisplayMode", D3D_GetAdapterDisplayMode}, {"CheckDeviceMultiSampleType", D3D_CheckDeviceMultiSampleType},
    {"GetDeviceCaps", D3D_GetDeviceCaps}, {"GetAdapterMonitor", D3D_GetAdapterMonitor}, {"CreateDevice", D3D_CreateDevice},
};

static void Direct3DCreate9_(CPU *c) {
    if (!vt_d3d) vt_d3d = VT(IDirect3D9, d3d_ov);
    fprintf(stderr, "[d3d9] Direct3DCreate9(sdk %#x)\n", ARG(c, 0));
    RET(c, newobj(vt_d3d, 0, 0, 0), 1);
}
static void D3DPERF_SetOptions_(CPU *c) { RET(c, 0, 1); }

const ShimTable d3d9_shims = { (const Shim[]){ {"Direct3DCreate9", Direct3DCreate9_}, {"D3DPERF_SetOptions", D3DPERF_SetOptions_} }, 2 };

// ---- entry points for d3dx9.c ------------------------------------------------------------------
uint32_t d3d9_create_texture(uint32_t dev, int cube, uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t fmt, uint32_t pool) {
    make_vtables();
    return new_texture(dev, cube ? K_CUBE : K_TEX, w, h, levels, usage, fmt, pool);
}
uint32_t d3d9_texture_level_data(uint32_t tex, uint32_t face, uint32_t level, uint32_t *pitch, uint32_t *size) {
    uint32_t s = tex_surf(tex, face, level);
    if (!s) return 0;
    *pitch = G32(OBJ_F(s, S_PITCH));
    uint32_t p, sz; level_layout(G32(OBJ_F(s, S_FMT)), G32(OBJ_F(s, S_W)), G32(OBJ_F(s, S_H)), &p, &sz);
    *size = sz;
    return surf_pin(s);                               // unpinned by d3d9_texture_dirty
}
void d3d9_texture_dirty(uint32_t tex) {
    for (uint32_t f = 0; f < G32(OBJ_F(tex, T_FACES)); f++)
        for (uint32_t l = 0; l < G32(OBJ_F(tex, T_LEVELS)); l++) { surf_unpin(tex_surf(tex, f, l)); d3d_backend_dirty(tex_surf(tex, f, l)); }
}
