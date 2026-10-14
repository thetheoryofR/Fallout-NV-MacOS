// Guest heap: size-class free lists for small blocks, a first-fit page allocator for large ones.
// Everything lives in [HEAP_LO, HEAP_HI) of the guest space so guest pointers stay 32-bit.
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include "host.h"

// one lock for the whole guest heap: the game allocates from many threads
static pthread_mutex_t hl = PTHREAD_MUTEX_INITIALIZER;
#define L pthread_mutex_lock(&hl)
#define UL pthread_mutex_unlock(&hl)

#define HEAP_LO 0x40000000u
#define HEAP_HI 0xF0000000u
#define HDR 16                       // [size:4][class:4][pad:8] before every block (16-aligned)
#define NCLASS 20                    // 16 B .. 8 MB
static uint32_t brk_ = HEAP_LO;
static uint32_t freelist[NCLASS];

static int cls(uint32_t n) { int c = 0; uint32_t s = 16; while (s < n && c < NCLASS - 1) { s <<= 1; c++; } return c; }
static uint32_t csize(int c) { return 16u << c; }

static uint32_t bump(uint32_t n) {
    uint32_t p = (brk_ + 15) & ~15u;
    if ((uint64_t)p + n > HEAP_HI) { fprintf(stderr, "[gheap] out of guest memory\n"); abort(); }
    brk_ = p + n;
    return p;
}

static uint32_t gmalloc_u(uint32_t size) {
    if (size == 0) size = 1;
    if (size > csize(NCLASS - 1) - HDR) {        // huge: dedicated pages, class = -1
        uint32_t p = bump(((size + HDR) + 0xFFF) & ~0xFFFu);
        P32(p, size); P32(p + 4, 0xFFFFFFFFu);
        return p + HDR;
    }
    int c = cls(size + HDR);
    uint32_t p = freelist[c];
    if (p) freelist[c] = G32(p + 8);
    else p = bump(csize(c));
    memset(MEM + p + HDR, 0, size);
    P32(p, size); P32(p + 4, (uint32_t)c);
    return p + HDR;
}

static void gfree_u(uint32_t q) {
    if (!q) return;
    uint32_t p = q - HDR, c = G32(p + 4);
    if (c == 0xFFFFFFFFu) return;                // huge blocks are not reused (rare)
    P32(p + 8, freelist[c]);
    freelist[c] = p;
}

uint32_t gsize(uint32_t q) { return q ? G32(q - HDR) : 0; }

static uint32_t grealloc_u(uint32_t q, uint32_t size) {
    if (!q) return gmalloc_u(size);
    uint32_t old = gsize(q);
    uint32_t c = G32(q - HDR + 4);
    if (c != 0xFFFFFFFFu && size + HDR <= csize((int)c)) { P32(q - HDR, size); return q; }
    uint32_t n = gmalloc_u(size);
    memcpy(MEM + n, MEM + q, old < size ? old : size);
    gfree_u(q);
    return n;
}

static uint32_t gpages_u(uint32_t size) {
    brk_ = (brk_ + 0xFFF) & ~0xFFFu;
    uint32_t p = bump((size + 0xFFF) & ~0xFFFu);
    memset(MEM + p, 0, size);
    return p;
}

uint32_t gmalloc(uint32_t size) { L; uint32_t r = gmalloc_u(size); UL; return r; }
void gfree(uint32_t q) { L; gfree_u(q); UL; }
uint32_t grealloc(uint32_t q, uint32_t size) { L; uint32_t r = grealloc_u(q, size); UL; return r; }
uint32_t gpages(uint32_t size) { L; uint32_t r = gpages_u(size); UL; return r; }
