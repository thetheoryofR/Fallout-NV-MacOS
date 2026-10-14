// Metal backend for the D3D9 layer (overrides the weak null backend).
//
// Model: every draw reads the guest-side D3D state (D3DState) and guest resources directly.
//  - textures/surfaces: one MTLTexture per guest surface/texture object, created on first use;
//    CPU-written levels are re-uploaded when marked dirty (Unlock / DDS load / UpdateSurface).
//  - vertex/index data: static buffers get their own MTLBuffer, re-created (not overwritten, so
//    in-flight frames keep the old contents) when the game unlocks them. D3DUSAGE_DYNAMIC buffers,
//    and static ones the game keeps rewriting, are copied per draw into a per-frame ring buffer.
//  - shaders: translated on first use by sm2msl; pipelines keyed by (vs, ps, vertex layout, render
//    target formats, blend state, sample count).
#import <AppKit/AppKit.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <ImageIO/ImageIO.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreVideo/CoreVideo.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "d3d9_backend.h"
#include "host.h"
#include "sm2msl.h"
#include "input.h"

// ---- guest object layout (mirrors d3d9.c) ---------------------------------------------------------
#define OBJ_KIND(o) G32((o) + 8)
#define OBJ_F(o, i) ((o) + 16 + 4 * (i))
enum { K_TEX = 1, K_CUBE, K_VOL, K_SURF, K_VB, K_IB, K_DECL, K_VS, K_PS };
enum { S_W, S_H, S_FMT, S_USAGE, S_POOL, S_DATA, S_PITCH, S_CONT, S_MS, S_LEVEL, S_DIRTY, S_HOST };
enum { T_W, T_H, T_LEVELS, T_FMT, T_USAGE, T_POOL, T_SURFS, T_FACES, T_LOD, T_DIRTY, T_HOST };
enum { B_LEN, B_USAGE, B_FMT, B_POOL, B_DATA, B_HOST, B_DIRTY, B_UPS };
#define FCC(a, b, c_, d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c_) << 16) | ((uint32_t)(d) << 24))

// ---- host-side state ------------------------------------------------------------------------------
static id<MTLDevice> dev;
static id<MTLCommandQueue> queue;
static CAMetalLayer *layer;
static NSWindow *window;
static id<MTLCommandBuffer> cmd;
static id<MTLRenderCommandEncoder> enc;
static uint32_t enc_rt[4], enc_ds;
static dispatch_semaphore_t inflight;
#define RING_SIZE (192u << 20)
static id<MTLBuffer> ring[3];
static uint32_t ring_idx, ring_off;
// ---- encoder state cache: skip Metal calls that would set what is already set in this encoder ----
static struct {
    __unsafe_unretained id pso, dss;
    int fixed_valid; uint32_t sref, cull, fill; float bias, slope; MTLViewport vp; MTLScissorRect sc; uint32_t bc;
    __unsafe_unretained id vbuf[32], fbuf[4]; NSUInteger voff[32], foff[4];
    int vb_valid[32], fb_valid[32];                 // set*Bytes slots: content below is current
    uint8_t vbytes[32][256], fbytes[4][256];
    __unsafe_unretained id ftex[16], fsamp[32], vtex[4], vsamp[4];
} ec;
static void ec_reset(void) { memset(&ec, 0, sizeof ec); }
static void ec_vbuf(id<MTLBuffer> b, NSUInteger off, int i) {
    if (ec.vbuf[i] == b) { if (ec.voff[i] != off) { [enc setVertexBufferOffset:off atIndex:i]; ec.voff[i] = off; } return; }
    [enc setVertexBuffer:b offset:off atIndex:i]; ec.vbuf[i] = b; ec.voff[i] = off; ec.vb_valid[i] = 0;
}
static void ec_fbuf(id<MTLBuffer> b, NSUInteger off, int i) {
    if (ec.fbuf[i] == b) { if (ec.foff[i] != off) { [enc setFragmentBufferOffset:off atIndex:i]; ec.foff[i] = off; } return; }
    [enc setFragmentBuffer:b offset:off atIndex:i]; ec.fbuf[i] = b; ec.foff[i] = off; ec.fb_valid[i] = 0;
}
static void ec_vbytes(const void *p, NSUInteger n, int i) {        // n <= 256
    if (ec.vb_valid[i] && !memcmp(ec.vbytes[i], p, n)) return;
    [enc setVertexBytes:p length:n atIndex:i]; memcpy(ec.vbytes[i], p, n); ec.vb_valid[i] = 1; ec.vbuf[i] = nil;
}
static void ec_fbytes(const void *p, NSUInteger n, int i) {        // i < 4, n <= 256
    if (ec.fb_valid[i] && !memcmp(ec.fbytes[i], p, n)) return;
    [enc setFragmentBytes:p length:n atIndex:i]; memcpy(ec.fbytes[i], p, n); ec.fb_valid[i] = 1; ec.fbuf[i] = nil;
}
// host objects live in a plain array; the guest object stores index+1 in its *_HOST field
// host objects: a plain table of +1-retained pointers; the guest object stores index+1 in its *_HOST
// field. Lookups return unretained pointers (no ARC traffic on the per-draw path).
static void **hostp; static uint32_t hostn, hostcap, *host_free, host_nfree, host_freecap;
static uint32_t host_field(uint32_t o) {
    uint32_t k = OBJ_KIND(o);
    if (k == K_TEX || k == K_CUBE) return OBJ_F(o, T_HOST);
    if (k == K_SURF) return OBJ_F(o, S_HOST);
    if (k == K_VB || k == K_IB) return OBJ_F(o, B_HOST);
    return OBJ_F(o, 2);                                       // shaders: code, ntok, host
}
static inline void *host_get(uint32_t o) { uint32_t i = G32(host_field(o)); return i ? hostp[i - 1] : NULL; }
static void host_set(uint32_t o, id v) {
    uint32_t i = G32(host_field(o));
    if (i) { if (hostp[i - 1]) CFRelease(hostp[i - 1]); hostp[i - 1] = (void *)CFBridgingRetain(v); return; }   // replace
    if (host_nfree) i = host_free[--host_nfree];
    else {
        if (hostn == hostcap) { hostcap = hostcap ? hostcap * 2 : 4096; hostp = realloc(hostp, sizeof *hostp * hostcap); }
        i = hostn++;
    }
    hostp[i] = (void *)CFBridgingRetain(v);
    P32(host_field(o), i + 1);
}
static void host_drop(uint32_t o) {
    uint32_t i = G32(host_field(o));
    if (!i) return;
    if (hostp[i - 1]) CFRelease(hostp[i - 1]);
    hostp[i - 1] = NULL;
    if (host_nfree == host_freecap) { host_freecap = host_freecap ? host_freecap * 2 : 4096; host_free = realloc(host_free, sizeof *host_free * host_freecap); }
    host_free[host_nfree++] = i - 1;
    P32(host_field(o), 0);
}

static uint64_t ff_skipped, draws_done;
static int trace_metal;
static pthread_mutex_t blk;
static pthread_once_t blk_once = PTHREAD_ONCE_INIT;
static void blk_init(void) { pthread_mutexattr_t a; pthread_mutexattr_init(&a); pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE); pthread_mutex_init(&blk, &a); }
#define LOCKED_BEGIN pthread_once(&blk_once, blk_init); pthread_mutex_lock(&blk);
#define LOCKED_END pthread_mutex_unlock(&blk);

// ---- formats ----------------------------------------------------------------------------------------
typedef struct { MTLPixelFormat pf; MTLTextureSwizzleChannels sw; int has_sw; } Fmt;
static Fmt fmt_map(uint32_t f) {
    Fmt r = {MTLPixelFormatInvalid, MTLTextureSwizzleChannelsMake(MTLTextureSwizzleRed, MTLTextureSwizzleGreen, MTLTextureSwizzleBlue, MTLTextureSwizzleAlpha), 0};
#define SW(a, b, c_, d) do { r.sw = MTLTextureSwizzleChannelsMake(MTLTextureSwizzle##a, MTLTextureSwizzle##b, MTLTextureSwizzle##c_, MTLTextureSwizzle##d); r.has_sw = 1; } while (0)
    switch (f) {
    case 21: r.pf = MTLPixelFormatBGRA8Unorm; break;
    case 22: r.pf = MTLPixelFormatBGRA8Unorm; SW(Red, Green, Blue, One); break;
    case 32: r.pf = MTLPixelFormatRGBA8Unorm; break;
    case 33: r.pf = MTLPixelFormatRGBA8Unorm; SW(Red, Green, Blue, One); break;
    case 23: r.pf = MTLPixelFormatB5G6R5Unorm; break;
    case 25: r.pf = MTLPixelFormatA1BGR5Unorm; break;
    case 24: r.pf = MTLPixelFormatA1BGR5Unorm; SW(Red, Green, Blue, One); break;
    case 26: r.pf = MTLPixelFormatABGR4Unorm; SW(Green, Blue, Alpha, Red); break;
    case 28: r.pf = MTLPixelFormatA8Unorm; break;
    case 50: r.pf = MTLPixelFormatR8Unorm; SW(Red, Red, Red, One); break;
    case 51: r.pf = MTLPixelFormatRG8Unorm; SW(Red, Red, Red, Green); break;
    case 60: r.pf = MTLPixelFormatRG8Snorm; SW(Red, Green, One, One); break;
    case 34: r.pf = MTLPixelFormatRG16Unorm; SW(Red, Green, One, One); break;
    case 35: r.pf = MTLPixelFormatBGR10A2Unorm; break;
    case 31: r.pf = MTLPixelFormatRGB10A2Unorm; break;
    case 36: r.pf = MTLPixelFormatRGBA16Unorm; break;
    case 111: r.pf = MTLPixelFormatR16Float; SW(Red, One, One, One); break;
    case 112: r.pf = MTLPixelFormatRG16Float; SW(Red, Green, One, One); break;
    case 113: r.pf = MTLPixelFormatRGBA16Float; break;
    case 114: r.pf = MTLPixelFormatR32Float; SW(Red, One, One, One); break;
    case 115: r.pf = MTLPixelFormatRG32Float; SW(Red, Green, One, One); break;
    case 116: r.pf = MTLPixelFormatRGBA32Float; break;
    case 80: case 70: r.pf = MTLPixelFormatDepth16Unorm; break;
    case 75: case 77: case 71: r.pf = MTLPixelFormatDepth32Float_Stencil8; break;
    default:
        if (f == FCC('D', 'X', 'T', '1')) r.pf = MTLPixelFormatBC1_RGBA;
        else if (f == FCC('D', 'X', 'T', '2') || f == FCC('D', 'X', 'T', '3')) r.pf = MTLPixelFormatBC2_RGBA;
        else if (f == FCC('D', 'X', 'T', '4') || f == FCC('D', 'X', 'T', '5')) r.pf = MTLPixelFormatBC3_RGBA;
        else if (f == FCC('A', 'T', 'I', '1')) { r.pf = MTLPixelFormatBC4_RUnorm; SW(Red, Red, Red, One); }
        else if (f == FCC('A', 'T', 'I', '2')) { r.pf = MTLPixelFormatBC5_RGUnorm; SW(Green, Red, One, One); }   // ATI2 stores Y in the first block
        else if (f == FCC('I', 'N', 'T', 'Z')) r.pf = MTLPixelFormatDepth32Float_Stencil8;
        else if (f == FCC('N', 'U', 'L', 'L')) r.pf = MTLPixelFormatInvalid;
        else r.pf = MTLPixelFormatBGRA8Unorm;
    }
#undef SW
    return r;
}
static int is_depth_fmt(uint32_t f) { return f == 80 || f == 70 || f == 75 || f == 77 || f == 71 || f == FCC('I', 'N', 'T', 'Z'); }

// ---- textures ---------------------------------------------------------------------------------------
@interface HTex : NSObject
@property(nonatomic, strong) id<MTLTexture> tex, view;   // view: swizzled / for sampling
@property(nonatomic) uint32_t fmt, w, h, levels, faces, ms;
@end
@implementation HTex
@end

static HTex *make_tex(uint32_t fmt, uint32_t w, uint32_t h, uint32_t levels, uint32_t faces, uint32_t ms, int rt) {
    Fmt f = fmt_map(fmt);
    if (f.pf == MTLPixelFormatInvalid) return nil;
    MTLTextureDescriptor *d = [MTLTextureDescriptor new];
    d.pixelFormat = f.pf; d.width = w ? w : 1; d.height = h ? h : 1; d.mipmapLevelCount = levels ? levels : 1;
    d.textureType = faces == 6 ? MTLTextureTypeCube : MTLTextureType2D;
    if (ms > 1 && faces == 1) { d.textureType = MTLTextureType2DMultisample; d.sampleCount = ms; d.mipmapLevelCount = 1; }
    d.usage = MTLTextureUsageShaderRead | (rt || is_depth_fmt(fmt) ? MTLTextureUsageRenderTarget : 0) | MTLTextureUsagePixelFormatView;
    d.storageMode = (rt || is_depth_fmt(fmt) || ms > 1) ? MTLStorageModePrivate : MTLStorageModeShared;
    HTex *t = [HTex new];
    t.tex = [dev newTextureWithDescriptor:d];
    t.fmt = fmt; t.w = w; t.h = h; t.levels = (uint32_t)d.mipmapLevelCount; t.faces = faces; t.ms = ms;
    t.view = f.has_sw && ms <= 1 ? [t.tex newTextureViewWithPixelFormat:f.pf textureType:d.textureType levels:NSMakeRange(0, t.levels)
                                                                slices:NSMakeRange(0, faces) swizzle:f.sw] : t.tex;
    return t;
}

static void upload_level(HTex *t, uint32_t surf, uint32_t face, uint32_t level) {
    if (t.tex.storageMode == MTLStorageModePrivate) return;           // GPU-written targets are not uploaded
    uint32_t w = G32(OBJ_F(surf, S_W)), h = G32(OBJ_F(surf, S_H)), pitch = G32(OBJ_F(surf, S_PITCH));
    int blk = d3d_fmt_block(t.fmt);
    uint32_t rows = blk ? (h + 3) / 4 : h;
    const uint8_t *bytes = d3d_surf_begin(surf);
    if (bytes) [t.tex replaceRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:level slice:face withBytes:bytes
                       bytesPerRow:pitch bytesPerImage:pitch * rows];
    d3d_surf_end();
}

// the host texture for a guest texture / surface object (created on first use, uploads pending dirt)
static HTex *host_tex(uint32_t o) __attribute__((ns_returns_not_retained));
static HTex *host_tex(uint32_t o) {
    if (!o) return nil;
    uint32_t kind = OBJ_KIND(o);
    if (kind == K_SURF && G32(OBJ_F(o, S_CONT))) return host_tex(G32(OBJ_F(o, S_CONT)));   // a level of a texture
    HTex *t = (__bridge HTex *)host_get(o);     // strong: the creation path below assigns new objects to it
    if (!t) {
        if (kind == K_TEX || kind == K_CUBE) {
            t = make_tex(G32(OBJ_F(o, T_FMT)), G32(OBJ_F(o, T_W)), G32(OBJ_F(o, T_H)), G32(OBJ_F(o, T_LEVELS)), G32(OBJ_F(o, T_FACES)), 1,
                         (G32(OBJ_F(o, T_USAGE)) & 3) != 0);
            if (!t) return nil;
            host_set(o, t);
            P32(OBJ_F(o, T_DIRTY), 1);
            for (uint32_t i = 0; i < t.levels * t.faces; i++) P32(OBJ_F(G32(G32(OBJ_F(o, T_SURFS)) + 4 * i), S_DIRTY), 1);
        } else if (kind == K_SURF) {
            t = make_tex(G32(OBJ_F(o, S_FMT)), G32(OBJ_F(o, S_W)), G32(OBJ_F(o, S_H)), 1, 1, G32(OBJ_F(o, S_MS)) > 1 ? G32(OBJ_F(o, S_MS)) : 1,
                         (G32(OBJ_F(o, S_USAGE)) & 3) != 0);
            if (!t) return nil;
            host_set(o, t);
            if (!(G32(OBJ_F(o, S_USAGE)) & 3)) upload_level(t, o, 0, 0);
            return t;
        } else return nil;
    }
    if ((kind == K_TEX || kind == K_CUBE) && G32(OBJ_F(o, T_DIRTY))) {
        P32(OBJ_F(o, T_DIRTY), 0);
        for (uint32_t f = 0; f < t.faces; f++)
            for (uint32_t l = 0; l < t.levels; l++) {
                uint32_t su = G32(G32(OBJ_F(o, T_SURFS)) + 4 * (f * t.levels + l));
                if (G32(OBJ_F(su, S_DIRTY))) { P32(OBJ_F(su, S_DIRTY), 0); upload_level(t, su, f, l); }
            }
    } else if (kind == K_SURF && G32(OBJ_F(o, S_DIRTY))) { P32(OBJ_F(o, S_DIRTY), 0); upload_level(t, o, 0, 0); }
    return t;
}
// the specific level/face slice a surface is (for render targets that are texture levels)
static id<MTLTexture> surf_target(uint32_t s, NSUInteger *level, NSUInteger *slice) {
    *level = 0; *slice = 0;
    if (!s) return nil;
    uint32_t cont = G32(OBJ_F(s, S_CONT));
    HTex *t = host_tex(s);
    if (cont) { uint32_t lv = G32(OBJ_F(s, S_LEVEL)); *level = lv & 0xFFFF; *slice = lv >> 16; }
    return t.tex;
}

// ---- shaders & pipelines ----------------------------------------------------------------------------
@interface HShader : NSObject {
@public
    SMInfo info;
    int nvar;
    uint32_t var_key[16];          // hash of (depth_mask, extras)
    __unsafe_unretained id<MTLFunction> var_fn[16];
}
@property(nonatomic, strong) NSMutableArray *keep;    // owns the functions
@end
@implementation HShader
@end

static MTLCompileOptions *copts;
static HShader *host_shader(uint32_t o) __attribute__((ns_returns_not_retained));
static HShader *host_shader(uint32_t o) {
    __unsafe_unretained HShader *h0 = (__bridge HShader *)host_get(o);
    if (h0) return h0;
    HShader *h;
    h = [HShader new];
    char err[256];
    if (!sm_reflect((const uint32_t *)(void *)(MEM + G32(OBJ_F(o, 0))), G32(OBJ_F(o, 1)), &h->info, err, sizeof err)) {
        fprintf(stderr, "[metal] shader %#x reflect failed: %s\n", o, err);
        return nil;
    }
    h.keep = [NSMutableArray array];
    host_set(o, h);
    return h;
}
static uint64_t stall_ns;                                   // time spent compiling shaders / pipelines
static id<MTLFunction> shader_fn(uint32_t o, HShader *h, const uint16_t *extra, int n_extra, uint32_t depth_mask) {
    uint32_t key = depth_mask * 2654435761u;
    for (int i = 0; i < n_extra; i++) key = (key ^ extra[i]) * 16777619u;
    for (int i = 0; i < h->nvar; i++) if (h->var_key[i] == key) return h->var_fn[i];
    SMInfo info = h->info; info.depth_mask_in = depth_mask;
    char err[256];
    char *msl = sm_translate((const uint32_t *)(void *)(MEM + G32(OBJ_F(o, 0))), G32(OBJ_F(o, 1)), &info, extra, n_extra, err, sizeof err);
    if (!msl) { fprintf(stderr, "[metal] translate failed: %s\n", err); return nil; }
    NSError *e = nil;
    uint64_t t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:msl] options:copts error:&e];
    uint64_t dt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - t0;
    stall_ns += dt;
    if (dt > 4000000) fprintf(stderr, "[metal] shader compile %.1f ms (%s)\n", (double)dt / 1e6, h->info.is_ps ? "ps" : "vs");
    free(msl);
    if (!lib) { fprintf(stderr, "[metal] compile failed: %s\n", e.localizedDescription.UTF8String); return nil; }
    id<MTLFunction> f = [lib newFunctionWithName:h->info.is_ps ? @"pmain" : @"vmain"];
    [h.keep addObject:f];
    if (h->nvar < 16) { h->var_key[h->nvar] = key; h->var_fn[h->nvar] = f; h->nvar++; }
    return f;
}

static MTLVertexFormat decl_fmt(int t) {
    switch (t) {
    case 0: return MTLVertexFormatFloat;  case 1: return MTLVertexFormatFloat2; case 2: return MTLVertexFormatFloat3; case 3: return MTLVertexFormatFloat4;
    case 4: return MTLVertexFormatUChar4Normalized_BGRA; case 5: return MTLVertexFormatUChar4; case 6: return MTLVertexFormatShort2;
    case 7: return MTLVertexFormatShort4; case 8: return MTLVertexFormatUChar4Normalized; case 9: return MTLVertexFormatShort2Normalized;
    case 10: return MTLVertexFormatShort4Normalized; case 11: return MTLVertexFormatUShort2Normalized; case 12: return MTLVertexFormatUShort4Normalized;
    case 13: return MTLVertexFormatUInt1010102Normalized; case 14: return MTLVertexFormatInt1010102Normalized;
    case 15: return MTLVertexFormatHalf2; case 16: return MTLVertexFormatHalf4;
    }
    return MTLVertexFormatInvalid;
}

// build the vertex descriptor: decl elements matched to VS input registers by (usage, index)
static MTLVertexDescriptor *vertex_desc(D3DState *s, const SMInfo *vi, uint32_t *streams_used, NSMutableString *key) {
    MTLVertexDescriptor *vd = [MTLVertexDescriptor vertexDescriptor];
    *streams_used = 0;
    if (!s->decl) return nil;
    uint32_t e = G32(OBJ_F(s->decl, 0)), n = G32(OBJ_F(s->decl, 1));
    for (uint32_t i = 0; i < n; i++, e += 8) {
        uint16_t stream, off; uint8_t type, method, usage, uidx;
        memcpy(&stream, MEM + e, 2); memcpy(&off, MEM + e + 2, 2); type = MEM[e + 4]; method = MEM[e + 5]; usage = MEM[e + 6]; uidx = MEM[e + 7];
        if (stream == 0xFF) break;
        (void)method;
        for (int r = 0; r < 16; r++) {
            if (vi->in_usage[r] != usage || vi->in_index[r] != uidx) continue;
            vd.attributes[r].format = decl_fmt(type); vd.attributes[r].offset = off; vd.attributes[r].bufferIndex = stream;
            *streams_used |= 1u << stream;
            [key appendFormat:@"a%d:%d:%d:%d;", r, type, off, stream];
        }
    }
    for (int st = 0; st < 16; st++) if (*streams_used & (1u << st)) {
        vd.layouts[st].stride = s->stream_stride[st] ? s->stream_stride[st] : 4;
        vd.layouts[st].stepFunction = MTLVertexStepFunctionPerVertex;
        [key appendFormat:@"s%d:%u;", st, s->stream_stride[st]];
    }
    return vd;
}

static MTLBlendFactor blendf(uint32_t b) {
    switch (b) {
    case 1: return MTLBlendFactorZero; case 2: return MTLBlendFactorOne; case 3: return MTLBlendFactorSourceColor;
    case 4: return MTLBlendFactorOneMinusSourceColor; case 5: return MTLBlendFactorSourceAlpha; case 6: return MTLBlendFactorOneMinusSourceAlpha;
    case 7: return MTLBlendFactorDestinationAlpha; case 8: return MTLBlendFactorOneMinusDestinationAlpha; case 9: return MTLBlendFactorDestinationColor;
    case 10: return MTLBlendFactorOneMinusDestinationColor; case 11: return MTLBlendFactorSourceAlphaSaturated;
    case 14: return MTLBlendFactorBlendColor; case 15: return MTLBlendFactorOneMinusBlendColor;
    }
    return MTLBlendFactorOne;
}
static MTLBlendOperation blendop(uint32_t o) {
    switch (o) { case 2: return MTLBlendOperationSubtract; case 3: return MTLBlendOperationReverseSubtract; case 4: return MTLBlendOperationMin; case 5: return MTLBlendOperationMax; }
    return MTLBlendOperationAdd;
}
static MTLCompareFunction cmpf(uint32_t f) {
    switch (f) {
    case 1: return MTLCompareFunctionNever; case 2: return MTLCompareFunctionLess; case 3: return MTLCompareFunctionEqual; case 4: return MTLCompareFunctionLessEqual;
    case 5: return MTLCompareFunctionGreater; case 6: return MTLCompareFunctionNotEqual; case 7: return MTLCompareFunctionGreaterEqual;
    }
    return MTLCompareFunctionAlways;
}
static MTLStencilOperation stencilop(uint32_t o) {
    switch (o) {
    case 2: return MTLStencilOperationZero; case 3: return MTLStencilOperationReplace; case 4: return MTLStencilOperationIncrementClamp;
    case 5: return MTLStencilOperationDecrementClamp; case 6: return MTLStencilOperationInvert; case 7: return MTLStencilOperationIncrementWrap;
    case 8: return MTLStencilOperationDecrementWrap;
    }
    return MTLStencilOperationKeep;
}

// ---- render passes ----------------------------------------------------------------------------------
static void end_pass(void) { if (enc) { [enc endEncoding]; enc = nil; } }

static void ensure_cmd(void) { if (!cmd) cmd = [queue commandBuffer]; }

static void begin_pass(D3DState *s, uint32_t clear_flags, uint32_t color, float z, uint32_t stencil) {
    end_pass(); ensure_cmd();
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    for (int i = 0; i < 4; i++) {
        NSUInteger lv, sl; id<MTLTexture> t = surf_target(s->rt[i], &lv, &sl);
        if (!t) continue;
        rp.colorAttachments[i].texture = t; rp.colorAttachments[i].level = lv; rp.colorAttachments[i].slice = sl;
        rp.colorAttachments[i].loadAction = (clear_flags & 1) ? MTLLoadActionClear : MTLLoadActionLoad;
        rp.colorAttachments[i].clearColor = MTLClearColorMake(((color >> 16) & 255) / 255.0, ((color >> 8) & 255) / 255.0, (color & 255) / 255.0, (color >> 24) / 255.0);
        rp.colorAttachments[i].storeAction = MTLStoreActionStore;
    }
    if (s->ds) {
        NSUInteger lv, sl; id<MTLTexture> t = surf_target(s->ds, &lv, &sl);
        if (t) {
            rp.depthAttachment.texture = t; rp.depthAttachment.loadAction = (clear_flags & 2) ? MTLLoadActionClear : MTLLoadActionLoad;
            rp.depthAttachment.clearDepth = z; rp.depthAttachment.storeAction = MTLStoreActionStore;
            if (t.pixelFormat == MTLPixelFormatDepth32Float_Stencil8) {
                rp.stencilAttachment.texture = t; rp.stencilAttachment.loadAction = (clear_flags & 4) ? MTLLoadActionClear : MTLLoadActionLoad;
                rp.stencilAttachment.clearStencil = stencil; rp.stencilAttachment.storeAction = MTLStoreActionStore;
            }
        }
    }
    enc = [cmd renderCommandEncoderWithDescriptor:rp];
    ec_reset();
    memcpy(enc_rt, s->rt, sizeof enc_rt); enc_ds = s->ds;
}
static void ensure_pass(D3DState *s) {
    if (enc && !memcmp(enc_rt, s->rt, sizeof enc_rt) && enc_ds == s->ds) return;
    begin_pass(s, 0, 0, 1, 0);
}

// ---- ring buffer --------------------------------------------------------------------------------------
static uint32_t ring_put(const void *p, uint32_t n) {
    uint32_t off = (ring_off + 255) & ~255u;
    if (off + n > RING_SIZE) { fprintf(stderr, "[metal] ring overflow (%u bytes this frame)\n", off + n); off = 0; }
    memcpy((uint8_t *)ring[ring_idx].contents + off, p, n);
    ring_off = off + n;
    return off;
}

// ---- draws ----------------------------------------------------------------------------------------------
typedef struct { uint32_t k[8]; __unsafe_unretained id<MTLSamplerState> st; } SampEnt;
static SampEnt samp_tab[1024];
static NSMutableArray *samp_keep;
static id<MTLSamplerState> sampler(D3DState *s, int i, int compare) {
    uint32_t *ss = s->ss[i];
    uint32_t k[8] = {ss[1], ss[2], ss[3], ss[5], ss[6], ss[7], ss[10], (uint32_t)compare};
    uint32_t h = 2166136261u; for (int j = 0; j < 8; j++) h = (h ^ k[j]) * 16777619u;
    for (uint32_t p = 0; p < 1024; p++) {
        SampEnt *e = &samp_tab[(h + p) & 1023];
        if (!e->st) break;
        if (!memcmp(e->k, k, sizeof k)) return e->st;
    }
    MTLSamplerDescriptor *d = [MTLSamplerDescriptor new];
    MTLSamplerAddressMode am[] = {MTLSamplerAddressModeRepeat, MTLSamplerAddressModeRepeat, MTLSamplerAddressModeMirrorRepeat,
                                  MTLSamplerAddressModeClampToEdge, MTLSamplerAddressModeClampToBorderColor, MTLSamplerAddressModeMirrorClampToEdge};
    d.sAddressMode = am[ss[1] < 6 ? ss[1] : 1]; d.tAddressMode = am[ss[2] < 6 ? ss[2] : 1]; d.rAddressMode = am[ss[3] < 6 ? ss[3] : 1];
    d.magFilter = ss[5] >= 2 ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
    d.minFilter = ss[6] >= 2 ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
    d.mipFilter = ss[7] == 0 ? MTLSamplerMipFilterNotMipmapped : ss[7] == 1 ? MTLSamplerMipFilterNearest : MTLSamplerMipFilterLinear;
    d.maxAnisotropy = (ss[6] == 3 || ss[5] == 3) ? (ss[10] ? ss[10] : 1) : 1;
    if (compare) { d.compareFunction = MTLCompareFunctionLessEqual; d.minFilter = d.magFilter = MTLSamplerMinMagFilterLinear; }
    id<MTLSamplerState> st = [dev newSamplerStateWithDescriptor:d];
    [samp_keep addObject:st];
    for (uint32_t p = 0; p < 1024; p++) {
        SampEnt *e = &samp_tab[(h + p) & 1023];
        if (!e->st) { memcpy(e->k, k, sizeof k); e->st = st; break; }
    }
    return st;
}

static int prim_info(uint32_t prim, uint32_t count, MTLPrimitiveType *pt, uint32_t *nverts) {
    switch (prim) {
    case 1: *pt = MTLPrimitiveTypePoint; *nverts = count; return 1;
    case 2: *pt = MTLPrimitiveTypeLine; *nverts = count * 2; return 1;
    case 3: *pt = MTLPrimitiveTypeLineStrip; *nverts = count + 1; return 1;
    case 4: *pt = MTLPrimitiveTypeTriangle; *nverts = count * 3; return 1;
    case 5: *pt = MTLPrimitiveTypeTriangleStrip; *nverts = count + 2; return 1;
    case 6: *pt = MTLPrimitiveTypeTriangle; *nverts = count * 3; return 2;     // fan: expanded
    }
    return 0;
}

// Everything a pipeline depends on, compared with memcmp.
typedef struct {
    uint32_t vs, ps, decl, depth_mask;
    uint32_t stride[8];
    uint32_t rtfmt[4], rtwm[4], dsfmt, samples;
    uint32_t blend_en, src, dst, op, sep, srca, dsta, opa;
} PipeKey;
typedef struct { PipeKey k; uint32_t streams; __unsafe_unretained id<MTLRenderPipelineState> pso; } PipeEnt;
#define PIPE_TAB 16384
static PipeEnt *pipe_tab;
static NSMutableArray *pipe_keep;
static uint32_t pipe_count;

typedef struct { uint32_t key; __unsafe_unretained id<MTLDepthStencilState> st; } DssEnt;
static DssEnt dss_tab[4096];
static NSMutableArray *dss_keep;
static uint32_t last_vs_off, last_ps_off, last_vs_n, last_ps_n, last_ring_for_consts = 99;

static uint32_t decl_streams(D3DState *s) {
    uint32_t e = G32(OBJ_F(s->decl, 0)), n = G32(OBJ_F(s->decl, 1)), m = 0;
    for (uint32_t i = 0; i < n; i++, e += 8) { uint16_t st; memcpy(&st, MEM + e, 2); if (st == 0xFF) break; if (st < 16) m |= 1u << st; }
    return m;
}

static int setup_draw(D3DState *s) {
    if (!s->vs || !s->ps) { ff_skipped++; return 0; }
    if (!s->decl) return 0;
    ensure_pass(s);
    PipeKey k; memset(&k, 0, sizeof k);
    k.vs = s->vs; k.ps = s->ps; k.decl = s->decl;
    for (int i = 0; i < 16; i++) {
        uint32_t t = s->tex[i];
        if (t && OBJ_KIND(t) == K_TEX && is_depth_fmt(G32(OBJ_F(t, T_FMT)))) k.depth_mask |= 1u << i;
    }
    for (int i = 0; i < 8; i++) k.stride[i] = s->stream_stride[i];
    for (int i = 0; i < 4; i++) {
        NSUInteger lv, sl; id<MTLTexture> t = surf_target(s->rt[i], &lv, &sl);
        if (!t) continue;
        k.rtfmt[i] = (uint32_t)t.pixelFormat; k.samples = (uint32_t)t.sampleCount;
        k.rtwm[i] = i == 0 ? s->rs[168] : s->rs[189 + i];
    }
    if (s->ds) { NSUInteger lv, sl; id<MTLTexture> t = surf_target(s->ds, &lv, &sl); if (t) { k.dsfmt = (uint32_t)t.pixelFormat; k.samples = (uint32_t)t.sampleCount; } }
    if (s->rs[27]) { k.blend_en = 1; k.src = s->rs[19]; k.dst = s->rs[20]; k.op = s->rs[171];
        if (s->rs[206]) { k.sep = 1; k.srca = s->rs[207]; k.dsta = s->rs[208]; k.opa = s->rs[209]; } }

    uint32_t h = 2166136261u; const uint32_t *kw = (const uint32_t *)&k;
    for (size_t i = 0; i < sizeof k / 4; i++) h = (h ^ kw[i]) * 16777619u;
    PipeEnt *pe = NULL;
    for (uint32_t p = 0; p < PIPE_TAB; p++) {
        PipeEnt *e = &pipe_tab[(h + p) & (PIPE_TAB - 1)];
        if (!e->pso) { pe = e; break; }
        if (!memcmp(&e->k, &k, sizeof k)) { pe = e; break; }
    }
    if (!pe) return 0;
    __unsafe_unretained HShader *vs = host_shader(s->vs), *ps = host_shader(s->ps);
    if (!vs || !ps) return 0;
    if (!pe->pso) {
        // miss: link the stages, translate/compile, describe vertices, build the pipeline
        uint16_t extra[16]; int ne = 0;
        for (int i = 0; i < ps->info.n_io; i++) {
            int found = 0;
            for (int j = 0; j < vs->info.n_io; j++) if (vs->info.io_keys[j] == ps->info.io_keys[i]) found = 1;
            if (!found && ne < 16) extra[ne++] = ps->info.io_keys[i];
        }
        id<MTLFunction> vf = shader_fn(s->vs, vs, extra, ne, 0), pf = shader_fn(s->ps, ps, NULL, 0, k.depth_mask);
        if (!vf || !pf) return 0;
        NSMutableString *unused = [NSMutableString string];
        uint32_t streams;
        SMInfo vi = vs->info;
        MTLVertexDescriptor *vd = vertex_desc(s, &vi, &streams, unused);
        if (!vd) return 0;
        MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
        pd.vertexFunction = vf; pd.fragmentFunction = pf; pd.vertexDescriptor = vd;
        for (int i = 0; i < 4; i++) {
            if (!k.rtfmt[i]) continue;
            pd.colorAttachments[i].pixelFormat = (MTLPixelFormat)k.rtfmt[i];
            uint32_t wm = k.rtwm[i];
            pd.colorAttachments[i].writeMask = (wm & 1 ? MTLColorWriteMaskRed : 0) | (wm & 2 ? MTLColorWriteMaskGreen : 0) | (wm & 4 ? MTLColorWriteMaskBlue : 0) | (wm & 8 ? MTLColorWriteMaskAlpha : 0);
            if (k.blend_en) {
                pd.colorAttachments[i].blendingEnabled = YES;
                pd.colorAttachments[i].sourceRGBBlendFactor = blendf(k.src); pd.colorAttachments[i].destinationRGBBlendFactor = blendf(k.dst);
                pd.colorAttachments[i].rgbBlendOperation = blendop(k.op);
                pd.colorAttachments[i].sourceAlphaBlendFactor = blendf(k.sep ? k.srca : k.src);
                pd.colorAttachments[i].destinationAlphaBlendFactor = blendf(k.sep ? k.dsta : k.dst);
                pd.colorAttachments[i].alphaBlendOperation = blendop(k.sep ? k.opa : k.op);
            }
        }
        if (k.dsfmt) { pd.depthAttachmentPixelFormat = (MTLPixelFormat)k.dsfmt; if (k.dsfmt == MTLPixelFormatDepth32Float_Stencil8) pd.stencilAttachmentPixelFormat = (MTLPixelFormat)k.dsfmt; }
        pd.rasterSampleCount = k.samples ? k.samples : 1;
        NSError *e = nil;
        uint64_t t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        id<MTLRenderPipelineState> pso = [dev newRenderPipelineStateWithDescriptor:pd error:&e];
        uint64_t dt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - t0;
        stall_ns += dt;
        if (dt > 4000000) fprintf(stderr, "[metal] pipeline build %.1f ms\n", (double)dt / 1e6);
        if (!pso) { fprintf(stderr, "[metal] pipeline failed: %s\n", e.localizedDescription.UTF8String); return 0; }
        [pipe_keep addObject:pso];
        pe->k = k; pe->pso = pso; pe->streams = streams; pipe_count++;
    }
    if (ec.pso != pe->pso) { [enc setRenderPipelineState:pe->pso]; ec.pso = pe->pso; }

    // depth / stencil
    uint32_t dkey = (s->rs[7] ? 1 : 0) | (s->rs[14] ? 2 : 0) | (s->rs[23] << 2) | (s->rs[52] ? 64 : 0) | (s->rs[56] << 7) | (s->rs[53] << 11) |
                    (s->rs[54] << 15) | (s->rs[55] << 19) | ((s->rs[58] & 0xFF) << 23);
    dkey ^= (s->rs[59] & 0xFF) * 2654435761u;
    id<MTLDepthStencilState> ds = nil;
    for (uint32_t p = 0; p < 4096; p++) {
        DssEnt *e = &dss_tab[(dkey * 2654435761u + p) & 4095];
        if (!e->st) {
            MTLDepthStencilDescriptor *dd = [MTLDepthStencilDescriptor new];
            dd.depthCompareFunction = s->rs[7] ? cmpf(s->rs[23]) : MTLCompareFunctionAlways;
            dd.depthWriteEnabled = s->rs[7] && s->rs[14];
            if (s->rs[52]) {
                MTLStencilDescriptor *sd = [MTLStencilDescriptor new];
                sd.stencilCompareFunction = cmpf(s->rs[56]); sd.stencilFailureOperation = stencilop(s->rs[53]);
                sd.depthFailureOperation = stencilop(s->rs[54]); sd.depthStencilPassOperation = stencilop(s->rs[55]);
                sd.readMask = s->rs[58]; sd.writeMask = s->rs[59];
                dd.frontFaceStencil = sd; dd.backFaceStencil = sd;
            }
            ds = [dev newDepthStencilStateWithDescriptor:dd];
            [dss_keep addObject:ds];
            e->key = dkey; e->st = ds;
            break;
        }
        if (e->key == dkey) { ds = e->st; break; }
    }
    if (ec.dss != ds) { [enc setDepthStencilState:ds]; ec.dss = ds; }
    uint32_t cull = s->rs[22] == 2 ? MTLCullModeFront : s->rs[22] == 3 ? MTLCullModeBack : MTLCullModeNone;
    uint32_t fill = s->rs[8] == 2 ? MTLTriangleFillModeLines : MTLTriangleFillModeFill;
    float bias, slope; memcpy(&bias, &s->rs[195], 4); memcpy(&slope, &s->rs[175], 4);
    float vpz0, vpz1; memcpy(&vpz0, &s->viewport[4], 4); memcpy(&vpz1, &s->viewport[5], 4);
    MTLViewport vp = {s->viewport[0], s->viewport[1], s->viewport[2], s->viewport[3], vpz0, vpz1};
    if (!ec.fixed_valid) [enc setFrontFacingWinding:MTLWindingClockwise];
    if (!ec.fixed_valid || ec.sref != s->rs[57]) { [enc setStencilReferenceValue:s->rs[57]]; ec.sref = s->rs[57]; }
    if (!ec.fixed_valid || ec.cull != cull) { [enc setCullMode:(MTLCullMode)cull]; ec.cull = cull; }
    if (!ec.fixed_valid || ec.fill != fill) { [enc setTriangleFillMode:(MTLTriangleFillMode)fill]; ec.fill = fill; }
    if (!ec.fixed_valid || ec.bias != bias || ec.slope != slope) { [enc setDepthBias:bias * 16777216.0f slopeScale:slope clamp:0]; ec.bias = bias; ec.slope = slope; }
    if (!ec.fixed_valid || memcmp(&ec.vp, &vp, sizeof vp)) { [enc setViewport:vp]; ec.vp = vp; }
    NSUInteger lv, sl; id<MTLTexture> rt0 = surf_target(s->rt[0], &lv, &sl);
    NSUInteger tw = rt0 ? MAX(1, rt0.width >> lv) : s->width, th = rt0 ? MAX(1, rt0.height >> lv) : s->height;
    MTLScissorRect sc = {0, 0, tw, th};
    if (s->rs[174]) {
        int x0 = (int)s->scissor[0], y0 = (int)s->scissor[1], x1 = (int)s->scissor[2], y1 = (int)s->scissor[3];
        x0 = MAX(0, MIN(x0, (int)tw)); x1 = MAX(x0, MIN(x1, (int)tw)); y0 = MAX(0, MIN(y0, (int)th)); y1 = MAX(y0, MIN(y1, (int)th));
        sc = (MTLScissorRect){(NSUInteger)x0, (NSUInteger)y0, (NSUInteger)(x1 - x0), (NSUInteger)(y1 - y0)};
    }
    if (!ec.fixed_valid || memcmp(&ec.sc, &sc, sizeof sc)) { [enc setScissorRect:sc]; ec.sc = sc; }
    uint32_t bc = s->rs[193];
    if (!ec.fixed_valid || ec.bc != bc) {
        [enc setBlendColorRed:((bc >> 16) & 255) / 255.0f green:((bc >> 8) & 255) / 255.0f blue:(bc & 255) / 255.0f alpha:(bc >> 24) / 255.0f];
        ec.bc = bc;
    }
    ec.fixed_valid = 1;

    // constants: re-upload only what changed since the last draw in this frame's ring
    // only the registers the bound shaders read (max_const from reflection); re-upload when the game
    // changed constants, the ring rotated, or this shader reads past what the last upload covered
    uint32_t vn = (uint32_t)(vs->info.max_const + 1), pn = (uint32_t)(ps->info.max_const + 1);
    if (vn > 256) vn = 256;
    if (pn > 224) pn = 224;
    if (s->vsc_dirty || last_ring_for_consts != ring_idx || vn > last_vs_n) {
        last_vs_off = ring_put(s->vsc, (vn ? vn : 1) * 16); last_vs_n = vn; s->vsc_dirty = 0;
    }
    if (s->psc_dirty || last_ring_for_consts != ring_idx || pn > last_ps_n) {
        last_ps_off = ring_put(s->psc, (pn ? pn : 1) * 16); last_ps_n = pn; s->psc_dirty = 0;
    }
    last_ring_for_consts = ring_idx;
    ec_vbuf(ring[ring_idx], last_vs_off, 20);
    ec_vbytes(s->vsi, sizeof s->vsi, 21);
    ec_vbytes(s->vsb, sizeof s->vsb, 22);
    float vsys[4] = {s->viewport[2] ? -1.0f / (float)s->viewport[2] : 0, s->viewport[3] ? 1.0f / (float)s->viewport[3] : 0, 0, 0};
    ec_vbytes(vsys, sizeof vsys, 23);
    ec_fbuf(ring[ring_idx], last_ps_off, 0);
    ec_fbytes(s->psi, sizeof s->psi, 1);
    ec_fbytes(s->psb, sizeof s->psb, 2);
    struct { uint32_t alpha_func; float alpha_ref; uint32_t fog_mode, fog_enable; float fog_color[4]; float fog_params[4]; uint32_t fog_table, p0, p1, p2; } psys;
    psys.alpha_func = s->rs[15] ? s->rs[25] : 8; psys.alpha_ref = (float)(s->rs[24] & 255) / 255.0f;
    psys.fog_enable = s->rs[28] && ps->info.major < 3; psys.fog_table = s->rs[35] != 0; psys.fog_mode = s->rs[35] ? s->rs[35] : s->rs[140];
    uint32_t fc = s->rs[34];
    psys.fog_color[0] = ((fc >> 16) & 255) / 255.0f; psys.fog_color[1] = ((fc >> 8) & 255) / 255.0f; psys.fog_color[2] = (fc & 255) / 255.0f; psys.fog_color[3] = 1;
    memcpy(&psys.fog_params[0], &s->rs[36], 4); memcpy(&psys.fog_params[1], &s->rs[37], 4); memcpy(&psys.fog_params[2], &s->rs[38], 4); psys.fog_params[3] = 0;
    psys.p0 = psys.p1 = psys.p2 = 0;
    _Static_assert(sizeof psys <= 256, "psys");
    ec_fbytes(&psys, sizeof psys, 3);

    for (int i = 0; i < 16; i++) {
        if (!(ps->info.samplers & (1u << i))) continue;
        __unsafe_unretained HTex *t = host_tex(s->tex[i]);
        if (!t) continue;
        id<MTLTexture> tv = (k.depth_mask >> i) & 1 ? t.tex : t.view;
        if (ec.ftex[i] != tv) { [enc setFragmentTexture:tv atIndex:i]; ec.ftex[i] = tv; }
        id<MTLSamplerState> sm = sampler(s, i, 0);
        if (ec.fsamp[i] != sm) { [enc setFragmentSamplerState:sm atIndex:i]; ec.fsamp[i] = sm; }
        if ((k.depth_mask >> i) & 1) {
            id<MTLSamplerState> sc2 = sampler(s, i, 1);
            if (ec.fsamp[i + 16] != sc2) { [enc setFragmentSamplerState:sc2 atIndex:i + 16]; ec.fsamp[i + 16] = sc2; }
        }
    }
    for (int i = 0; i < 4; i++) {
        if (!(vs->info.samplers & (1u << i))) continue;
        __unsafe_unretained HTex *t = host_tex(s->tex[16 + i]);
        if (t) {
            if (ec.vtex[i] != t.view) { [enc setVertexTexture:t.view atIndex:i]; ec.vtex[i] = t.view; }
            id<MTLSamplerState> sm = sampler(s, 16 + i, 0);
            if (ec.vsamp[i] != sm) { [enc setVertexSamplerState:sm atIndex:i]; ec.vsamp[i] = sm; }
        }
    }
    return (int)pe->streams | 0x10000;
}

// A static buffer's GPU copy, or nil when it must go through the ring (dynamic / keeps changing).
#define BUF_STREAMING 8u                                     // uploads after which a buffer counts as streaming
static id<MTLBuffer> static_buf(uint32_t b) __attribute__((ns_returns_not_retained));
static id<MTLBuffer> static_buf(uint32_t b) {
    if (G32(OBJ_F(b, B_USAGE)) & 0x200) return nil;            // D3DUSAGE_DYNAMIC
    uint32_t ups = G32(OBJ_F(b, B_UPS));
    if (ups >= BUF_STREAMING) return nil;
    __unsafe_unretained id<MTLBuffer> h = (__bridge id<MTLBuffer>)host_get(b);
    if (h && !G32(OBJ_F(b, B_DIRTY))) return h;
    uint32_t len = G32(OBJ_F(b, B_LEN));
    if (!len) return nil;
    P32(OBJ_F(b, B_DIRTY), 0); P32(OBJ_F(b, B_UPS), ups + 1);
    if (ups + 1 >= BUF_STREAMING) return nil;
    id<MTLBuffer> m = [dev newBufferWithBytes:MEM + G32(OBJ_F(b, B_DATA)) length:len options:MTLResourceStorageModeShared];
    host_set(b, m);
    return m;
}

static void bind_streams(D3DState *s, uint32_t streams, uint32_t first_vertex, uint32_t nverts) {
    for (int st = 0; st < 16; st++) {
        if (!(streams & (1u << st))) continue;
        uint32_t b = s->stream[st];
        if (!b) continue;
        uint32_t stride = s->stream_stride[st], len = G32(OBJ_F(b, B_LEN)), data = G32(OBJ_F(b, B_DATA));
        uint32_t start = s->stream_off[st] + first_vertex * stride, n = nverts * stride + 64;
        if (start >= len) continue;
        if (start + n > len) n = len - start;
        __unsafe_unretained id<MTLBuffer> sb = (start & 3) ? nil : static_buf(b);
        if (sb) { ec_vbuf(sb, start, st); continue; }
        uint32_t off = ring_put(MEM + data + start, n);
        ec_vbuf(ring[ring_idx], off, st);
    }
}

static void d3d_backend_draw_impl(D3DState *s, uint32_t prim, uint32_t start, uint32_t count, int indexed, int32_t base_vertex, uint32_t min_index, uint32_t num_vertices) {
    s->draws++;
    if (!count) return;
    int r = setup_draw(s);
    if (!r) return;
    MTLPrimitiveType pt; uint32_t n;
    int kind = prim_info(prim, count, &pt, &n);
    if (!kind) return;
    if (!indexed) {
        bind_streams(s, (uint32_t)r & 0xFFFF, start, n);
        if (kind == 2) {   // fan -> list indices
            uint16_t *ix = malloc(sizeof(uint16_t) * n);
            for (uint32_t i = 0; i < count; i++) { ix[3 * i] = 0; ix[3 * i + 1] = (uint16_t)(i + 1); ix[3 * i + 2] = (uint16_t)(i + 2); }
            uint32_t off = ring_put(ix, 2 * n); free(ix);
            [enc drawIndexedPrimitives:pt indexCount:n indexType:MTLIndexTypeUInt16 indexBuffer:ring[ring_idx] indexBufferOffset:off];
        } else [enc drawPrimitives:pt vertexStart:0 vertexCount:n];
    } else {
        uint32_t ib = s->indices;
        if (!ib) return;
        int i32 = G32(OBJ_F(ib, B_FMT)) == 102;
        uint32_t isz = i32 ? 4 : 2, idata = G32(OBJ_F(ib, B_DATA));
        // vertices the indices can touch: [base+min, base+min+num_vertices)
        bind_streams(s, (uint32_t)r & 0xFFFF, (uint32_t)(base_vertex + (int32_t)min_index), num_vertices);
        if (kind == 2) return;   // indexed fans: not used by FNV
        __unsafe_unretained id<MTLBuffer> ibuf = ((start * isz) & 3) ? nil : static_buf(ib);
        uint32_t ioff = ibuf ? start * isz : ring_put(MEM + idata + start * isz, n * isz);
        [enc drawIndexedPrimitives:pt indexCount:n indexType:i32 ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16 indexBuffer:ibuf ? ibuf : ring[ring_idx]
                 indexBufferOffset:ioff instanceCount:1 baseVertex:-(NSInteger)min_index baseInstance:0];
    }
    draws_done++;
}

static void d3d_backend_draw_up_impl(D3DState *s, uint32_t prim, uint32_t count, uint32_t vdata, uint32_t vstride, uint32_t idata, uint32_t ifmt, uint32_t min_index, uint32_t num_vertices) {
    s->draws++;
    if (!count || !vdata) return;
    uint32_t saved_stride = s->stream_stride[0];
    s->stream_stride[0] = vstride;
    int r = setup_draw(s);
    s->stream_stride[0] = saved_stride;
    if (!r) return;
    MTLPrimitiveType pt; uint32_t n;
    int kind = prim_info(prim, count, &pt, &n);
    if (!kind) return;
    uint32_t nv = idata ? min_index + num_vertices : n;
    uint32_t off = ring_put(MEM + vdata, nv * vstride);
    ec_vbuf(ring[ring_idx], off, 0);
    if (idata) {
        uint32_t isz = ifmt == 102 ? 4 : 2, ioff = ring_put(MEM + idata, n * isz);
        [enc drawIndexedPrimitives:pt indexCount:n indexType:isz == 4 ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16 indexBuffer:ring[ring_idx] indexBufferOffset:ioff];
    } else if (kind == 2) {
        uint16_t *ix = malloc(sizeof(uint16_t) * n);
        for (uint32_t i = 0; i < count; i++) { ix[3 * i] = 0; ix[3 * i + 1] = (uint16_t)(i + 1); ix[3 * i + 2] = (uint16_t)(i + 2); }
        uint32_t ioff = ring_put(ix, 2 * n); free(ix);
        [enc drawIndexedPrimitives:pt indexCount:n indexType:MTLIndexTypeUInt16 indexBuffer:ring[ring_idx] indexBufferOffset:ioff];
    } else [enc drawPrimitives:pt vertexStart:0 vertexCount:n];
    draws_done++;
}

static void d3d_backend_clear_impl(D3DState *s, uint32_t count, uint32_t rects, uint32_t flags, uint32_t color, float z, uint32_t stencil) {
    (void)count; (void)rects;   // partial-rect clears are treated as full clears for now
    begin_pass(s, flags, color, z, stencil);
}

// ---- blits ------------------------------------------------------------------------------------------
static id<MTLRenderPipelineState> blit_pso[8];
static id<MTLRenderPipelineState> blit_pipeline(MTLPixelFormat pf) {
    static NSMutableDictionary *cache;
    if (!cache) cache = [NSMutableDictionary dictionary];
    id<MTLRenderPipelineState> p = cache[@(pf)];
    if (p) return p;
    static id<MTLLibrary> lib;
    if (!lib) {
        NSString *src = @"#include <metal_stdlib>\nusing namespace metal;\n"
            "struct V { float4 p [[position]]; float2 uv; };\n"
            "vertex V bv(uint i [[vertex_id]], constant float4 &r [[buffer(0)]]) { float2 q = float2((i << 1) & 2, i & 2); V v; v.p = float4(q * 2.0 - 1.0, 0, 1); v.p.y = -v.p.y; v.uv = r.xy + q * r.zw; return v; }\n"
            "fragment float4 bf(V v [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) { return t.sample(s, v.uv); }\n";
        lib = [dev newLibraryWithSource:src options:copts error:nil];
    }
    MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
    d.vertexFunction = [lib newFunctionWithName:@"bv"]; d.fragmentFunction = [lib newFunctionWithName:@"bf"];
    d.colorAttachments[0].pixelFormat = pf;
    p = [dev newRenderPipelineStateWithDescriptor:d error:nil];
    cache[@(pf)] = p;
    (void)blit_pso;
    return p;
}
static void blit(id<MTLTexture> src, id<MTLTexture> dst, NSUInteger dlevel, NSUInteger dslice, int linear) {
    if (!src || !dst) return;
    end_pass(); ensure_cmd();
    if (src.sampleCount > 1) {   // MSAA resolve
        MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
        rp.colorAttachments[0].texture = src; rp.colorAttachments[0].loadAction = MTLLoadActionLoad;
        rp.colorAttachments[0].storeAction = MTLStoreActionMultisampleResolve;
        rp.colorAttachments[0].resolveTexture = dst; rp.colorAttachments[0].resolveLevel = dlevel; rp.colorAttachments[0].resolveSlice = dslice;
        [[cmd renderCommandEncoderWithDescriptor:rp] endEncoding];
        return;
    }
    if (src.width == (dst.width >> dlevel) && src.height == (dst.height >> dlevel) && src.pixelFormat == dst.pixelFormat) {
        id<MTLBlitCommandEncoder> b = [cmd blitCommandEncoder];
        [b copyFromTexture:src sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(src.width, src.height, 1)
                 toTexture:dst destinationSlice:dslice destinationLevel:dlevel destinationOrigin:MTLOriginMake(0, 0, 0)];
        [b endEncoding];
        return;
    }
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture = dst; rp.colorAttachments[0].level = dlevel; rp.colorAttachments[0].slice = dslice;
    rp.colorAttachments[0].loadAction = MTLLoadActionDontCare; rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    id<MTLRenderCommandEncoder> e = [cmd renderCommandEncoderWithDescriptor:rp];
    [e setRenderPipelineState:blit_pipeline(dst.pixelFormat)];
    float r[4] = {0, 0, 1, 1};
    [e setVertexBytes:r length:16 atIndex:0];
    [e setFragmentTexture:src atIndex:0];
    MTLSamplerDescriptor *sd = [MTLSamplerDescriptor new];
    sd.minFilter = sd.magFilter = linear ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
    [e setFragmentSamplerState:[dev newSamplerStateWithDescriptor:sd] atIndex:0];
    [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    [e endEncoding];
}
static void d3d_backend_stretch_impl(D3DState *s, uint32_t src, uint32_t srect, uint32_t dst, uint32_t drect, uint32_t filter) {
    (void)s; (void)srect; (void)drect;
    NSUInteger sl, ss, dl, dsl;
    id<MTLTexture> a = surf_target(src, &sl, &ss), b = surf_target(dst, &dl, &dsl);
    if (a && b && !(a.pixelFormat >= MTLPixelFormatDepth16Unorm && a.pixelFormat <= MTLPixelFormatX24_Stencil8)) blit(a, b, dl, dsl, filter >= 2);
}
static void d3d_backend_colorfill_impl(D3DState *s, uint32_t surf, uint32_t rect, uint32_t color) {
    (void)rect;
    uint32_t saved[4]; memcpy(saved, s->rt, sizeof saved); uint32_t sd = s->ds;
    memset(s->rt, 0, sizeof s->rt); s->rt[0] = surf; s->ds = 0;
    begin_pass(s, 1, color, 1, 0);
    end_pass();
    memcpy(s->rt, saved, sizeof saved); s->ds = sd;
}
static void d3d_backend_readback_impl(D3DState *s, uint32_t rt, uint32_t dst) { (void)s; (void)rt; (void)dst; }   // TODO: screenshots / GPU readback

// ---- resource lifetime --------------------------------------------------------------------------------
// Shader prewarm: the game creates (nearly) all its shaders at boot. Translate each one's default
// variant now and compile it on background threads; the compiled result lands in Metal's on-disk
// shader cache, so the draw-time compile of that variant later is a cache hit instead of a stall of
// up to ~130 ms. Results are discarded here; FNV_NO_PREWARM=1 disables.
static void prewarm_shader(uint32_t o) {
    static int off = -1;
    static dispatch_queue_t q; static dispatch_semaphore_t width;
    if (off < 0) {
        off = getenv("FNV_NO_PREWARM") != NULL;
        q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
        width = dispatch_semaphore_create(4);
    }
    if (off) return;
    SMInfo info; char err[256];
    const uint32_t *tok = (const uint32_t *)(void *)(MEM + G32(OBJ_F(o, 0)));
    uint32_t ntok = G32(OBJ_F(o, 1));
    if (!sm_reflect(tok, ntok, &info, err, sizeof err)) return;
    info.depth_mask_in = 0;
    char *msl = sm_translate(tok, ntok, &info, NULL, 0, err, sizeof err);
    if (!msl) return;
    NSString *src = [NSString stringWithUTF8String:msl];
    free(msl);
    dispatch_async(q, ^{
        dispatch_semaphore_wait(width, DISPATCH_TIME_FOREVER);
        @autoreleasepool { (void)[dev newLibraryWithSource:src options:copts error:nil]; }
        dispatch_semaphore_signal(width);
    });
}
static void d3d_backend_created_impl(uint32_t o) {
    if (o && (OBJ_KIND(o) == K_VS || OBJ_KIND(o) == K_PS)) prewarm_shader(o);
}
static void d3d_backend_dirty_impl(uint32_t o) {
    if (!o) return;
    if (OBJ_KIND(o) == K_VB || OBJ_KIND(o) == K_IB) { P32(OBJ_F(o, B_DIRTY), 1); return; }
    if (OBJ_KIND(o) != K_SURF) return;
    P32(OBJ_F(o, S_DIRTY), 1);
    uint32_t cont = G32(OBJ_F(o, S_CONT));
    if (cont) P32(OBJ_F(cont, T_DIRTY), 1);
}
static void d3d_backend_release_impl(uint32_t o) {
    uint32_t k = OBJ_KIND(o);
    if (k != K_TEX && k != K_CUBE && k != K_SURF && k != K_VS && k != K_PS && k != K_VB && k != K_IB) return;
    uint32_t i = G32(host_field(o));
    if (!i) return;
    if (k == K_TEX || k == K_CUBE || k == K_SURF) { memset(ec.ftex, 0, sizeof ec.ftex); memset(ec.vtex, 0, sizeof ec.vtex); }
    if (k == K_VB || k == K_IB) memset(ec.vbuf, 0, sizeof ec.vbuf);
    host_drop(o);
}

// ---- window / present ---------------------------------------------------------------------------------
@interface FNVView : NSView
@end
@implementation FNVView
- (CALayer *)makeBackingLayer { return [CAMetalLayer layer]; }
- (BOOL)wantsUpdateLayer { return YES; }
- (BOOL)acceptsFirstResponder { return YES; }
@end


// FNV_DUMP_FRAMES="300,1200,..." : save those frames' backbuffer as frame_<n>.png (GPU readback)
static int want_dump(uint64_t f) {
    static char list[512]; static int init;
    if (!init) { init = 1; const char *e = getenv("FNV_DUMP_FRAMES"); if (e) snprintf(list, sizeof list, ",%s,", e); }
    if (!list[0]) return 0;
    char k[32]; snprintf(k, sizeof k, ",%llu,", (unsigned long long)f);
    return strstr(list, k) != NULL;
}
static void dump_png(id<MTLTexture> src, uint64_t frame) {
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:src.width height:src.height mipmapped:NO];
    d.storageMode = MTLStorageModeShared; d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    id<MTLTexture> t = [dev newTextureWithDescriptor:d];
    blit(src, t, 0, 0, 0);
    end_pass();
    [cmd commit]; [cmd waitUntilCompleted]; cmd = nil; ensure_cmd();
    size_t w = t.width, h = t.height, bpr = w * 4;
    uint8_t *px = malloc(bpr * h);
    [t getBytes:px bytesPerRow:bpr fromRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(px, w, h, 8, bpr, cs, kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little);
    CGImageRef img = CGBitmapContextCreateImage(ctx);
    char path[256]; snprintf(path, sizeof path, "frame_%llu.png", (unsigned long long)frame);
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    CGImageDestinationRef dst = CGImageDestinationCreateWithURL(url, (__bridge CFStringRef)UTTypePNG.identifier, 1, NULL);
    CGImageDestinationAddImage(dst, img, NULL); CGImageDestinationFinalize(dst);
    CFRelease(dst); CFRelease(url); CGImageRelease(img); CGContextRelease(ctx); CGColorSpaceRelease(cs); free(px);
    fprintf(stderr, "[metal] dumped %s (%zux%zu)\n", path, w, h);
}

// ---- recorder ---------------------------------------------------------------------------------------------
// FNV_RECORD=<file.mov> : every presented frame is scaled on the GPU into a pooled CVPixelBuffer and
// appended to a hardware H.264 stream with its wall-clock timestamp. Fragmented, so a killed run still
// leaves a playable file. FNV_RECORD_SIZE=WxH (default 1920x1080).
static AVAssetWriter *rec_writer;
static AVAssetWriterInput *rec_input;
static AVAssetWriterInputPixelBufferAdaptor *rec_adaptor;
static CVMetalTextureCacheRef rec_cache;
static dispatch_queue_t rec_q;
static uint64_t rec_t0, rec_frames, rec_dropped;
static int rec_w, rec_h, rec_on;
static void rec_finish(void) {
    if (!rec_on) return;
    rec_on = 0;
    dispatch_sync(rec_q, ^{});
    [rec_input markAsFinished];
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    [rec_writer finishWritingWithCompletionHandler:^{ dispatch_semaphore_signal(done); }];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    fprintf(stderr, "[rec] finished %s: %llu frames, %llu dropped, status %ld\n", rec_writer.outputURL.path.UTF8String,
            (unsigned long long)rec_frames, (unsigned long long)rec_dropped, (long)rec_writer.status);
}
static void rec_init(void) {
    const char *path = getenv("FNV_RECORD");
    if (!path) return;
    rec_w = 1920; rec_h = 1080;
    const char *sz = getenv("FNV_RECORD_SIZE");
    if (sz) sscanf(sz, "%dx%d", &rec_w, &rec_h);
    NSURL *url = [NSURL fileURLWithPath:@(path)];
    [[NSFileManager defaultManager] removeItemAtURL:url error:nil];
    NSError *err = nil;
    rec_writer = [AVAssetWriter assetWriterWithURL:url fileType:AVFileTypeQuickTimeMovie error:&err];
    if (!rec_writer) { fprintf(stderr, "[rec] %s\n", err.localizedDescription.UTF8String); return; }
    rec_writer.movieFragmentInterval = CMTimeMake(5, 1);
    NSDictionary *vs = @{AVVideoCodecKey: AVVideoCodecTypeH264, AVVideoWidthKey: @(rec_w), AVVideoHeightKey: @(rec_h),
                         AVVideoCompressionPropertiesKey: @{AVVideoAverageBitRateKey: @(16000000), AVVideoExpectedSourceFrameRateKey: @60,
                                                            AVVideoMaxKeyFrameIntervalKey: @120}};
    rec_input = [AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo outputSettings:vs];
    rec_input.expectsMediaDataInRealTime = YES;
    rec_adaptor = [AVAssetWriterInputPixelBufferAdaptor assetWriterInputPixelBufferAdaptorWithAssetWriterInput:rec_input
        sourcePixelBufferAttributes:@{(id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA), (id)kCVPixelBufferWidthKey: @(rec_w),
                                      (id)kCVPixelBufferHeightKey: @(rec_h), (id)kCVPixelBufferMetalCompatibilityKey: @YES,
                                      (id)kCVPixelBufferIOSurfacePropertiesKey: @{}}];
    [rec_writer addInput:rec_input];
    if (![rec_writer startWriting]) { fprintf(stderr, "[rec] startWriting: %s\n", rec_writer.error.localizedDescription.UTF8String); return; }
    [rec_writer startSessionAtSourceTime:kCMTimeZero];
    CVMetalTextureCacheCreate(NULL, NULL, dev, NULL, &rec_cache);
    rec_q = dispatch_queue_create("fnv.rec", DISPATCH_QUEUE_SERIAL);
    rec_on = 1;
    atexit(rec_finish);
    fprintf(stderr, "[rec] recording %dx%d to %s\n", rec_w, rec_h, path);
}
// called inside present, before the command buffer is committed
static void rec_frame(id<MTLTexture> src) {
    if (!rec_on || !src || src.sampleCount > 1) return;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (!rec_t0) rec_t0 = now;
    if (!rec_input.readyForMoreMediaData || !rec_adaptor.pixelBufferPool) { rec_dropped++; return; }
    CVPixelBufferRef pb = NULL;
    if (CVPixelBufferPoolCreatePixelBuffer(NULL, rec_adaptor.pixelBufferPool, &pb) != kCVReturnSuccess) { rec_dropped++; return; }
    CVMetalTextureRef mt = NULL;
    CVMetalTextureCacheCreateTextureFromImage(NULL, rec_cache, pb, NULL, MTLPixelFormatBGRA8Unorm, (size_t)rec_w, (size_t)rec_h, 0, &mt);
    id<MTLTexture> dst = mt ? CVMetalTextureGetTexture(mt) : nil;
    if (!dst) { if (mt) CFRelease(mt); CVPixelBufferRelease(pb); rec_dropped++; return; }
    blit(src, dst, 0, 0, 1);
    CMTime t = CMTimeMake((int64_t)((now - rec_t0) / 1000), 1000000);
    [cmd addCompletedHandler:^(id<MTLCommandBuffer> b) {
        (void)b;
        dispatch_async(rec_q, ^{
            if (rec_on && rec_input.readyForMoreMediaData && [rec_adaptor appendPixelBuffer:pb withPresentationTime:t]) rec_frames++;
            else rec_dropped++;
            CFRelease(mt); CVPixelBufferRelease(pb);
        });
    }];
}

void d3d_backend_init(D3DState *s) {
    trace_metal = getenv("FNV_TRACE_METAL") != NULL;
    dev = MTLCreateSystemDefaultDevice();
    queue = [dev newCommandQueue];
    copts = [MTLCompileOptions new];
    copts.mathMode = MTLMathModeSafe;

    pipe_tab = calloc(PIPE_TAB, sizeof *pipe_tab); pipe_keep = [NSMutableArray array];
    samp_keep = [NSMutableArray array]; dss_keep = [NSMutableArray array];
    for (int i = 0; i < 3; i++) ring[i] = [dev newBufferWithLength:RING_SIZE options:MTLResourceStorageModeShared | MTLResourceCPUCacheModeWriteCombined];
    rec_init();
    inflight = dispatch_semaphore_create(3);

    if (getenv("FNV_HEADLESS")) {          // offscreen: real rendering, no window, no focus change
        fprintf(stderr, "[metal] %s, offscreen %ux%u\n", dev.name.UTF8String, s->width, s->height);
        dispatch_semaphore_wait(inflight, DISPATCH_TIME_FOREVER);
        return;
    }
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    CGFloat scale = [NSScreen mainScreen].backingScaleFactor;
    NSRect vis = [NSScreen mainScreen].visibleFrame;
    CGFloat w = s->width / scale, h = s->height / scale, fit = MIN(1.0, MIN(vis.size.width / w, (vis.size.height - 28) / h));
    NSRect r = NSMakeRect(0, 0, floor(w * fit), floor(h * fit));   // the drawable stays at the game's resolution
    window = [[NSWindow alloc] initWithContentRect:r styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable
                                           backing:NSBackingStoreBuffered defer:NO];
    window.title = @"Fallout: New Vegas (native)";
    FNVView *v = [[FNVView alloc] initWithFrame:r];
    v.wantsLayer = YES;
    window.contentView = v;
    layer = (CAMetalLayer *)v.layer;
    layer.device = dev; layer.pixelFormat = MTLPixelFormatBGRA8Unorm; layer.framebufferOnly = NO;
    layer.drawableSize = CGSizeMake(s->width, s->height);
    layer.displaySyncEnabled = getenv("FNV_NOVSYNC") ? NO : YES;
    layer.maximumDrawableCount = 3;
    [window center];
    [window makeKeyAndOrderFront:nil];
    [NSApp finishLaunching];
    [NSApp activateIgnoringOtherApps:YES];
    fprintf(stderr, "[metal] %s, window %ux%u (scale %.0f), vsync %s\n", dev.name.UTF8String, s->width, s->height, scale, layer.displaySyncEnabled ? "on" : "off");
    dispatch_semaphore_wait(inflight, DISPATCH_TIME_FOREVER);
}
static void d3d_backend_resize_impl(D3DState *s) { layer.drawableSize = CGSizeMake(s->width, s->height); }

// macOS virtual key code -> DirectInput scancode (DIK_*)
static const uint8_t mac2dik[128] = {
    [0x00] = 0x1E, [0x01] = 0x1F, [0x02] = 0x20, [0x03] = 0x21, [0x04] = 0x23, [0x05] = 0x22, [0x06] = 0x2C, [0x07] = 0x2D,
    [0x08] = 0x2E, [0x09] = 0x2F, [0x0B] = 0x30, [0x0C] = 0x10, [0x0D] = 0x11, [0x0E] = 0x12, [0x0F] = 0x13, [0x10] = 0x15,
    [0x11] = 0x14, [0x12] = 0x02, [0x13] = 0x03, [0x14] = 0x04, [0x15] = 0x05, [0x16] = 0x07, [0x17] = 0x06, [0x18] = 0x0D,
    [0x19] = 0x0A, [0x1A] = 0x08, [0x1B] = 0x0C, [0x1C] = 0x09, [0x1D] = 0x0B, [0x1E] = 0x1B, [0x1F] = 0x18, [0x20] = 0x16,
    [0x21] = 0x1A, [0x22] = 0x17, [0x23] = 0x19, [0x24] = 0x1C, [0x25] = 0x26, [0x26] = 0x24, [0x27] = 0x28, [0x28] = 0x25,
    [0x29] = 0x27, [0x2A] = 0x2B, [0x2B] = 0x33, [0x2C] = 0x35, [0x2D] = 0x31, [0x2E] = 0x32, [0x2F] = 0x34, [0x30] = 0x0F,
    [0x31] = 0x39, [0x32] = 0x29, [0x33] = 0x0E, [0x35] = 0x01, [0x37] = 0xDB, [0x38] = 0x2A, [0x39] = 0x3A, [0x3A] = 0x38,
    [0x3B] = 0x1D, [0x3C] = 0x36, [0x3D] = 0xB8, [0x3E] = 0x9D, [0x41] = 0x53, [0x43] = 0x37, [0x45] = 0x4E, [0x4B] = 0xB5,
    [0x4C] = 0x9C, [0x4E] = 0x4A, [0x52] = 0x52, [0x53] = 0x4F, [0x54] = 0x50, [0x55] = 0x51, [0x56] = 0x4B, [0x57] = 0x4C,
    [0x58] = 0x4D, [0x59] = 0x47, [0x5B] = 0x48, [0x5C] = 0x49, [0x60] = 0x3F, [0x61] = 0x40, [0x62] = 0x41, [0x63] = 0x3D,
    [0x64] = 0x42, [0x65] = 0x43, [0x67] = 0x57, [0x6D] = 0x44, [0x6F] = 0x58, [0x72] = 0xD2, [0x73] = 0xC7, [0x74] = 0xC9,
    [0x75] = 0xD3, [0x76] = 0x3E, [0x77] = 0xCF, [0x78] = 0x3C, [0x79] = 0xD1, [0x7A] = 0x3B, [0x7B] = 0xCB, [0x7C] = 0xCD,
    [0x7D] = 0xD0, [0x7E] = 0xC8,
};
static void handle_event(NSEvent *e) {
    switch (e.type) {
    case NSEventTypeKeyDown: case NSEventTypeKeyUp:
        if (e.keyCode < 128) input_key(mac2dik[e.keyCode], e.type == NSEventTypeKeyDown);
        return;
    case NSEventTypeFlagsChanged: {
        NSEventModifierFlags f = e.modifierFlags;
        input_key(0x2A, (f & NSEventModifierFlagShift) != 0); input_key(0x1D, (f & NSEventModifierFlagControl) != 0);
        input_key(0x38, (f & NSEventModifierFlagOption) != 0); input_key(0x3A, (f & NSEventModifierFlagCapsLock) != 0);
        return;
    }
    case NSEventTypeMouseMoved: case NSEventTypeLeftMouseDragged: case NSEventTypeRightMouseDragged: case NSEventTypeOtherMouseDragged:
        input_mouse_move((int)lround(e.deltaX), (int)lround(e.deltaY)); return;
    case NSEventTypeLeftMouseDown: input_mouse_button(0, 1); return;
    case NSEventTypeLeftMouseUp: input_mouse_button(0, 0); return;
    case NSEventTypeRightMouseDown: input_mouse_button(1, 1); return;
    case NSEventTypeRightMouseUp: input_mouse_button(1, 0); return;
    case NSEventTypeOtherMouseDown: input_mouse_button((int)e.buttonNumber, 1); return;
    case NSEventTypeOtherMouseUp: input_mouse_button((int)e.buttonNumber, 0); return;
    case NSEventTypeScrollWheel: input_mouse_wheel((int)lround(e.scrollingDeltaY * 40)); return;
    default: return;
    }
}
void host_pump_events(void) {
    if (!layer || ![NSThread isMainThread]) return;      // AppKit events belong to the main thread
    @autoreleasepool {
        static BOOL captured;
        BOOL key = window.isKeyWindow;
        if (key != captured) {                            // relative mouse while the game window is active
            captured = key;
            CGAssociateMouseAndMouseCursorPosition(!key);
            if (key) [NSCursor hide]; else [NSCursor unhide];
        }
        NSEvent *e;
        while ((e = [NSApp nextEventMatchingMask:NSEventMaskAny untilDate:nil inMode:NSDefaultRunLoopMode dequeue:YES])) {
            if (e.window == window || e.type == NSEventTypeFlagsChanged) handle_event(e);
            if (e.type != NSEventTypeKeyDown && e.type != NSEventTypeKeyUp) [NSApp sendEvent:e];   // no system beep for game keys
        }
    }
}

static void d3d_backend_present_impl(D3DState *s) {
    @autoreleasepool {
        end_pass(); ensure_cmd();
        id<CAMetalDrawable> drawable = layer ? [layer nextDrawable] : nil;
        HTex *bb = host_tex(s->backbuffer);
        if (bb && (want_dump(s->frames + 1) || input_take_dump_request())) dump_png(bb.tex, s->frames + 1);
        if (drawable && bb) blit(bb.tex, drawable.texture, 0, 0, 1);
        if (bb) rec_frame(bb.tex);
        if (drawable) [cmd presentDrawable:drawable];
        dispatch_semaphore_t sem = inflight;
        [cmd addCompletedHandler:^(id<MTLCommandBuffer> b) { (void)b; dispatch_semaphore_signal(sem); }];
        [cmd commit];
        cmd = nil;
        dispatch_semaphore_wait(inflight, DISPATCH_TIME_FOREVER);
        ring_idx = (ring_idx + 1) % 3; ring_off = 0;
        // stats
        static uint64_t t0, f0, d0;
        uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        if (!t0) t0 = now;
        s->frames++;
        { static uint64_t prev_draws; input_frame_draws(s->draws - prev_draws); prev_draws = s->draws; }
        input_script_tick(s->frames);
        if (now - t0 >= 2000000000ull) {
            double sec = (double)(now - t0) / 1e9;
            fprintf(stderr, "[metal] frame %llu: %.1f fps, %.0f draws/frame (%.0f rendered), %lu pipelines, ff-skipped %llu\n",
                    (unsigned long long)s->frames, (double)(s->frames - f0) / sec, (double)(s->draws - d0) / (double)(s->frames - f0),
                    (double)draws_done / (double)(s->frames - f0), (unsigned long)pipe_count, (unsigned long long)ff_skipped);
            t0 = now; f0 = s->frames; d0 = s->draws; draws_done = 0;
        }
    }
}

// ---- locked public entry points -----------------------------------------------------------------------
void d3d_backend_draw(D3DState *s, uint32_t p, uint32_t a, uint32_t n, int ix, int32_t bv, uint32_t mi, uint32_t nv) { LOCKED_BEGIN d3d_backend_draw_impl(s, p, a, n, ix, bv, mi, nv); LOCKED_END }
void d3d_backend_draw_up(D3DState *s, uint32_t p, uint32_t n, uint32_t vd, uint32_t vs, uint32_t id, uint32_t ifm, uint32_t mi, uint32_t nv) { LOCKED_BEGIN d3d_backend_draw_up_impl(s, p, n, vd, vs, id, ifm, mi, nv); LOCKED_END }
void d3d_backend_clear(D3DState *s, uint32_t c, uint32_t r, uint32_t f, uint32_t col, float z, uint32_t st) { LOCKED_BEGIN d3d_backend_clear_impl(s, c, r, f, col, z, st); LOCKED_END }
void d3d_backend_stretch(D3DState *s, uint32_t a, uint32_t b, uint32_t d, uint32_t e, uint32_t f) { LOCKED_BEGIN d3d_backend_stretch_impl(s, a, b, d, e, f); LOCKED_END }
void d3d_backend_colorfill(D3DState *s, uint32_t a, uint32_t b, uint32_t c) { LOCKED_BEGIN d3d_backend_colorfill_impl(s, a, b, c); LOCKED_END }
void d3d_backend_readback(D3DState *s, uint32_t a, uint32_t b) { LOCKED_BEGIN d3d_backend_readback_impl(s, a, b); LOCKED_END }
void d3d_backend_created(uint32_t o) { LOCKED_BEGIN d3d_backend_created_impl(o); LOCKED_END }
void d3d_backend_dirty(uint32_t o) { LOCKED_BEGIN d3d_backend_dirty_impl(o); LOCKED_END }
void d3d_backend_release(uint32_t o) { LOCKED_BEGIN d3d_backend_release_impl(o); LOCKED_END }
void d3d_backend_present(D3DState *s) { LOCKED_BEGIN d3d_backend_present_impl(s); LOCKED_END host_pump_events(); }
void d3d_backend_resize(D3DState *s) { LOCKED_BEGIN d3d_backend_resize_impl(s); LOCKED_END }
