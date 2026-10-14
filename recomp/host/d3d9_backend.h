#pragma once
#include <stdint.h>

// Everything the device knows; a backend renders from this at draw/present time.
typedef struct D3DState {
    uint8_t pp[56];
    uint32_t width, height, hwnd, d3d;
    uint32_t backbuffer, swapchain, ds, rt[4];
    uint32_t viewport[6];             // x, y, w, h, minZ(f32), maxZ(f32)
    uint32_t scissor[4];
    float transform[512][16];
    uint32_t rs[256];
    uint32_t tex[32];                 // 0-15 pixel samplers, 16-19 vertex samplers
    uint32_t tss[8][33];
    uint32_t ss[32][14];
    uint32_t vs, ps, decl, fvf;
    float vsc[256][4], psc[224][4];
    uint32_t vsb[16], psb[16];
    int32_t vsi[16][4], psi[16][4];
    uint32_t stream[16], stream_off[16], stream_stride[16], stream_freq[16];
    uint32_t indices;
    uint64_t frames, draws;
    int vsc_dirty, psc_dirty;            // constants changed since the backend last uploaded them
} D3DState;

int d3d_fmt_block(uint32_t fmt);
int d3d_fmt_bpp(uint32_t fmt);

void d3d_backend_init(D3DState *s);
void d3d_backend_resize(D3DState *s);
void d3d_backend_created(uint32_t obj);              // resource / shader created
void d3d_backend_dirty(uint32_t obj);                // CPU wrote it (Unlock)
void d3d_backend_release(uint32_t obj);              // refcount hit zero
void d3d_backend_clear(D3DState *s, uint32_t count, uint32_t rects, uint32_t flags, uint32_t color, float z, uint32_t stencil);
void d3d_backend_draw(D3DState *s, uint32_t prim, uint32_t start_or_minidx, uint32_t count, int indexed,
                      int32_t base_vertex, uint32_t min_index, uint32_t num_vertices);
void d3d_backend_draw_up(D3DState *s, uint32_t prim, uint32_t count, uint32_t vdata, uint32_t vstride,
                         uint32_t idata, uint32_t ifmt, uint32_t min_index, uint32_t num_vertices);
void d3d_backend_stretch(D3DState *s, uint32_t src, uint32_t srect, uint32_t dst, uint32_t drect, uint32_t filter);
void d3d_backend_colorfill(D3DState *s, uint32_t surf, uint32_t rect, uint32_t color);
void d3d_backend_readback(D3DState *s, uint32_t rt, uint32_t dst);
void d3d_backend_present(D3DState *s);

// surface bytes (d3d9.c), wherever they currently live — NULL if never written. The residency lock is
// held from begin to end.
const uint8_t *d3d_surf_begin(uint32_t surf);
void d3d_surf_end(void);
