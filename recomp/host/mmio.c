// winmm multimedia file I/O (RIFF chunk navigation) used by the sound loader.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "shims.h"

typedef struct { int fd; uint32_t buf, bufsize; } Mmio;
#define FCC(a, b, c_, d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c_) << 16) | ((uint32_t)(d) << 24))
enum { H_MMIO = 40 };
#define MMIOERR_CHUNKNOTFOUND 265
#define MMIOERR_CANNOTREAD 259

static Mmio *mm(uint32_t h) { return handle_get(h, H_MMIO); }

static void mmioOpenA_(CPU *c) {
    const char *name = GSTR(ARG(c, 0));
    char p[1024]; host_path(name ? name : "", p, sizeof p);
    int fd = open(p, O_RDONLY);
    if (fd < 0) { RET(c, 0, 3); return; }
    Mmio *m = calloc(1, sizeof *m); m->fd = fd;
    RET(c, handle_new(H_MMIO, m), 3);
}
static void mmioClose_(CPU *c) { Mmio *m = mm(ARG(c, 0)); if (m) { close(m->fd); if (m->buf) gfree(m->buf); free(m); handle_close(ARG(c, 0)); } RET(c, 0, 2); }
static void mmioRead_(CPU *c) {
    Mmio *m = mm(ARG(c, 0));
    ssize_t r = m ? read(m->fd, MEM + ARG(c, 1), ARG(c, 2)) : -1;
    RET(c, r < 0 ? 0xFFFFFFFFu : (uint32_t)r, 3);
}
// MMCKINFO: ckid, cksize, fccType, dwDataOffset, dwFlags
static void mmioDescend_(CPU *c) {
    Mmio *m = mm(ARG(c, 0)); uint32_t ck = ARG(c, 1), parent = ARG(c, 2), flags = ARG(c, 3);
    if (!m) { RET(c, MMIOERR_CANNOTREAD, 4); return; }
    uint32_t want_id = G32(ck), want_type = G32(ck + 8);
    off_t limit = parent ? (off_t)(G32(parent + 12) + G32(parent + 4)) : (off_t)1 << 40;
    for (;;) {
        off_t at = lseek(m->fd, 0, SEEK_CUR);
        if (at + 8 > limit) { RET(c, MMIOERR_CHUNKNOTFOUND, 4); return; }
        uint32_t hdr[3];
        if (read(m->fd, hdr, 8) != 8) { RET(c, MMIOERR_CHUNKNOTFOUND, 4); return; }
        uint32_t id = hdr[0], size = hdr[1], type = 0;
        int container = id == FCC('R', 'I', 'F', 'F') || id == FCC('L', 'I', 'S', 'T');
        if (container && read(m->fd, &type, 4) != 4) { RET(c, MMIOERR_CHUNKNOTFOUND, 4); return; }
        int match = 1;
        if (flags & 0x10) match = id == want_id;                                   // MMIO_FINDCHUNK
        if (flags & 0x20) match = id == FCC('R', 'I', 'F', 'F') && type == want_type; // MMIO_FINDRIFF
        if (flags & 0x40) match = id == FCC('L', 'I', 'S', 'T') && type == want_type; // MMIO_FINDLIST
        if (match) {
            P32(ck, id); P32(ck + 4, size); P32(ck + 8, type);
            P32(ck + 12, (uint32_t)(at + 8)); P32(ck + 16, 0);
            RET(c, 0, 4); return;
        }
        lseek(m->fd, at + 8 + size + (size & 1), SEEK_SET);                    // skip (chunks are word-aligned)
    }
}
static void mmioAscend_(CPU *c) {
    Mmio *m = mm(ARG(c, 0)); uint32_t ck = ARG(c, 1);
    if (m) { uint32_t size = G32(ck + 4); lseek(m->fd, (off_t)(G32(ck + 12) + size + (size & 1)), SEEK_SET); }
    RET(c, 0, 3);
}
// buffered access: MMIOINFO fields used: cchBuffer(+20) pchBuffer(+24) pchNext(+28) pchEndRead(+32)
// pchEndWrite(+36) lBufOffset(+40) lDiskOffset(+44)
static void mmioGetInfo_(CPU *c) {
    Mmio *m = mm(ARG(c, 0)); uint32_t info = ARG(c, 1);
    if (!m) { RET(c, MMIOERR_CANNOTREAD, 3); return; }
    if (!m->buf) { m->bufsize = 0x10000; m->buf = gmalloc(m->bufsize); }
    off_t pos = lseek(m->fd, 0, SEEK_CUR);
    memset(MEM + info, 0, 72);
    P32(info + 20, m->bufsize); P32(info + 24, m->buf); P32(info + 28, m->buf); P32(info + 32, m->buf); P32(info + 36, m->buf);
    P32(info + 40, (uint32_t)pos); P32(info + 44, (uint32_t)pos); P32(info + 68, ARG(c, 0));
    RET(c, 0, 3);
}
static void mmioAdvance_(CPU *c) {
    Mmio *m = mm(ARG(c, 0)); uint32_t info = ARG(c, 1);
    if (!m || !info) { RET(c, MMIOERR_CANNOTREAD, 3); return; }
    // the guest consumed up to pchNext: continue reading the file from there
    uint32_t consumed = G32(info + 28) - G32(info + 24);
    off_t next = (off_t)G32(info + 40) + consumed;
    lseek(m->fd, next, SEEK_SET);
    ssize_t r = read(m->fd, MEM + m->buf, m->bufsize);
    if (r < 0) r = 0;
    P32(info + 24, m->buf); P32(info + 28, m->buf); P32(info + 32, m->buf + (uint32_t)r);
    P32(info + 40, (uint32_t)next); P32(info + 44, (uint32_t)(next + r));
    RET(c, 0, 3);
}

const ShimTable mmio_shims = { (const Shim[]){
    {"mmioOpenA", mmioOpenA_}, {"mmioClose", mmioClose_}, {"mmioRead", mmioRead_}, {"mmioDescend", mmioDescend_},
    {"mmioAscend", mmioAscend_}, {"mmioGetInfo", mmioGetInfo_}, {"mmioAdvance", mmioAdvance_},
}, 7 };
