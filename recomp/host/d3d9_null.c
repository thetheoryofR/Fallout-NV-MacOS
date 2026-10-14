// Null D3D9 backend (M2): renders nothing, counts frames and draws, reports the frame rate.
// Selected when the Metal backend is not linked (weak symbols) — the Metal backend overrides these.
#include <stdio.h>
#include <time.h>
#include "d3d9_backend.h"

#define WEAK __attribute__((weak))
WEAK void host_pump_events(void) {}
WEAK void d3d_backend_init(D3DState *s) { fprintf(stderr, "[d3d9] null backend (headless): %ux%u\n", s->width, s->height); }
WEAK void d3d_backend_resize(D3DState *s) { (void)s; }
WEAK void d3d_backend_created(uint32_t o) { (void)o; }
WEAK void d3d_backend_dirty(uint32_t o) { (void)o; }
WEAK void d3d_backend_release(uint32_t o) { (void)o; }
WEAK void d3d_backend_clear(D3DState *s, uint32_t a, uint32_t b, uint32_t f, uint32_t col, float z, uint32_t st) { (void)s; (void)a; (void)b; (void)f; (void)col; (void)z; (void)st; }
WEAK void d3d_backend_draw(D3DState *s, uint32_t p, uint32_t a, uint32_t n, int ix, int32_t bv, uint32_t mi, uint32_t nv) { (void)p; (void)a; (void)n; (void)ix; (void)bv; (void)mi; (void)nv; s->draws++; }
WEAK void d3d_backend_draw_up(D3DState *s, uint32_t p, uint32_t n, uint32_t vd, uint32_t vs, uint32_t id, uint32_t ifm, uint32_t mi, uint32_t nv) { (void)p; (void)n; (void)vd; (void)vs; (void)id; (void)ifm; (void)mi; (void)nv; s->draws++; }
WEAK void d3d_backend_stretch(D3DState *s, uint32_t a, uint32_t b, uint32_t d, uint32_t e, uint32_t f) { (void)s; (void)a; (void)b; (void)d; (void)e; (void)f; }
WEAK void d3d_backend_colorfill(D3DState *s, uint32_t a, uint32_t b, uint32_t col) { (void)s; (void)a; (void)b; (void)col; }
WEAK void d3d_backend_readback(D3DState *s, uint32_t a, uint32_t b) { (void)s; (void)a; (void)b; }
WEAK void d3d_backend_present(D3DState *s) {
    static uint64_t t0, last_frames, last_draws;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (!t0) t0 = now;
    s->frames++;
    if (now - t0 >= 2000000000ull) {
        double sec = (double)(now - t0) / 1e9;
        fprintf(stderr, "[d3d9] frame %llu: %.1f fps, %.0f draws/frame\n", (unsigned long long)s->frames,
                (double)(s->frames - last_frames) / sec, (double)(s->draws - last_draws) / (double)(s->frames - last_frames));
        t0 = now; last_frames = s->frames; last_draws = s->draws;
    }
}
