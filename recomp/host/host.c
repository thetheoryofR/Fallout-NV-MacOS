// M2 host: loads a 32-bit PE image into the guest address space, binds its imports to native
// shims, builds the main thread (stack + TEB) and runs the recompiled entry point.
//
//   fnvhost <game.exe> [args...]
//
// An import with no shim stops the run and names itself — that list is the M2 work queue.
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <pthread/qos.h>
#include "../rt.h"
#include "host.h"
int host_run_guest(CPU *c, uint32_t entry);

uint8_t *MEM;
int64_t rt_budget = INT64_MAX;
static _Thread_local jmp_buf *trap_jb;
static _Thread_local int trap_code;
static _Thread_local uint32_t trap_addr;

void rt_trap(CPU *c, int code, uint32_t addr) {
    (void)c;
    trap_code = code;
    trap_addr = addr;
    longjmp(*trap_jb, 1);
}

static const char *trap_name(int code) {
    switch (code) {
    case TRAP_BUDGET: return "budget";
    case TRAP_BRANCHIND: return "unresolved indirect branch";
    case TRAP_DIV0: return "divide by zero";
    case TRAP_FALLOUT: return "fell out of function";
    case TRAP_UNSUPPORTED: return "unsupported/not emitted";
    case TRAP_NOFN: return "no function at address";
    case TRAP_INT3: return "int3";
    case TRAP_IMPORT: return "unimplemented import";
    default: return "?";
    }
}

static uint32_t rd32(uint32_t a) { uint32_t v; memcpy(&v, MEM + a, 4); return v; }
static uint16_t rd16(uint32_t a) { uint16_t v; memcpy(&v, MEM + a, 2); return v; }

// ---- imports ---------------------------------------------------------------------------------
HostImport host_imports[MAX_IMPORTS];
int host_import_count;

static void bind_imports(uint32_t base) {
    uint32_t pe = base + rd32(base + 0x3C);
    uint32_t imp = rd32(pe + 24 + 96 + 8);
    if (!imp) return;
    for (uint32_t d = base + imp; rd32(d + 12); d += 20) {
        const char *dll = (const char *)MEM + base + rd32(d + 12);
        uint32_t ilt = rd32(d) ? base + rd32(d) : base + rd32(d + 16);
        uint32_t iat = base + rd32(d + 16);
        for (; rd32(ilt); ilt += 4, iat += 4) {
            uint32_t e = rd32(ilt);
            HostImport *hi = &host_imports[host_import_count];
            snprintf(hi->dll, sizeof hi->dll, "%s", dll);
            if (e & 0x80000000u) snprintf(hi->name, sizeof hi->name, "#%u", e & 0xFFFF);
            else snprintf(hi->name, sizeof hi->name, "%s", (const char *)MEM + base + e + 2);
            hi->fn = host_find_shim(hi->dll, hi->name);
            uint32_t thunk = IMPORT_THUNK_BASE + 4 * host_import_count;
            memcpy(MEM + iat, &thunk, 4);
            host_import_count++;
        }
    }
}

// called by rt_call for addresses in the thunk range
void rt_import_call(CPU *c, uint32_t addr) {
    int i = (int)((addr - IMPORT_THUNK_BASE) / 4);
    if (i < 0 || i >= host_import_count) rt_trap(c, TRAP_NOFN, addr);
    HostImport *hi = &host_imports[i];
    if (!hi->fn) {
        fprintf(stderr, "[host] unimplemented import %s!%s\n", hi->dll, hi->name);
        rt_trap(c, TRAP_IMPORT, addr);
    }
    static int trace = -1;
    if (trace < 0) trace = getenv("FNV_TRACE") != NULL;
    if (trace) fprintf(stderr, "[imp] %s!%s(%#x, %#x, %#x, %#x)\n", hi->dll, hi->name,
                       G32(REG(c, R_ESP) + 4), G32(REG(c, R_ESP) + 8), G32(REG(c, R_ESP) + 12), G32(REG(c, R_ESP) + 16));
    hi->fn(c);
    if (trace) fprintf(stderr, "[imp]   -> %#x\n", REG(c, R_EAX));
}

// ---- loader ----------------------------------------------------------------------------------
static uint32_t load_pe(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *d = malloc(n);
    if (fread(d, 1, n, f) != (size_t)n) { perror("read"); exit(1); }
    fclose(f);
    uint32_t pe; memcpy(&pe, d + 0x3C, 4);
    uint32_t base, soh, ep; uint16_t nsec, osz;
    memcpy(&nsec, d + pe + 6, 2); memcpy(&osz, d + pe + 20, 2);
    memcpy(&ep, d + pe + 24 + 16, 4); memcpy(&base, d + pe + 24 + 28, 4); memcpy(&soh, d + pe + 24 + 60, 4);
    memcpy(MEM + base, d, soh);
    for (int i = 0; i < nsec; i++) {
        uint8_t *s = d + pe + 24 + osz + 40 * i;
        uint32_t vs, va, rs, rp;
        memcpy(&vs, s + 8, 4); memcpy(&va, s + 12, 4); memcpy(&rs, s + 16, 4); memcpy(&rp, s + 20, 4);
        uint32_t take = rs < vs || !vs ? rs : vs;
        memcpy(MEM + base + va, d + rp, take);
    }
    // static TLS (__declspec(thread)): snapshot the template; host_thread_init gives every thread its
    // own copy in TLS array[index], as the Windows loader does
    uint32_t tls_rva; memcpy(&tls_rva, d + pe + 24 + 96 + 9 * 8, 4);
    if (tls_rva) {
        uint32_t td[5]; memcpy(td, MEM + base + tls_rva, sizeof td);   // start, end, &index, &callbacks, zerofill
        host_tls_template_size = td[1] - td[0];
        host_tls_block_size = host_tls_template_size + td[4];
        host_tls_template = malloc(host_tls_template_size + 1);
        memcpy(host_tls_template, MEM + td[0], host_tls_template_size);
        P32(td[2], 0);                                                    // our module's TLS index
        uint32_t cb = td[3] ? G32(td[3]) : 0;
        fprintf(stderr, "[host] static TLS: %u-byte template + %u zero-fill%s\n", host_tls_template_size, td[4],
                cb ? " (TLS callbacks present: NOT run)" : "");
    }
    free(d);
    host_image_base = base;
    return base + ep;
}

uint32_t host_image_base;
uint8_t *host_tls_template;
uint32_t host_tls_template_size, host_tls_block_size;

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s game.exe [args]\n", argv[0]); return 2; }
    // at RT_MEM_BASE, so code compiled with RT_FIXED_MEM can address guest memory by constant
    void *p = mmap((void *)RT_MEM_BASE, (size_t)1 << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) { perror("mmap 4GB"); return 1; }
    if (p != (void *)RT_MEM_BASE) { fprintf(stderr, "[host] guest space landed at %p, not %#llx\n", p, RT_MEM_BASE); return 1; }
    MEM = p;
    // the game's main thread runs the frame: keep it on performance cores ahead of the game's workers
    // (a CLI process otherwise starts at default QoS and can land on efficiency cores)
    if (!getenv("FNV_NO_QOS")) pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    host_init_args(argc - 1, argv + 1);
    uint32_t entry = load_pe(argv[1]);
    bind_imports(host_image_base);
    fprintf(stderr, "[host] image @%#x, entry %#x, %d imports (%d shimmed)\n", host_image_base, entry,
            host_import_count, host_shimmed_count());

    static CPU cpu;
    CPU *c = &cpu;
    host_thread_init(c, 1 << 20);
    ST(c->r + 4256, 0x027F, 2);              // FPU control word as the MSVC CRT expects
    // push a return address that ends the run cleanly
    uint32_t esp = (uint32_t)LD(c->r + 16, 4) - 4;
    memcpy(MEM + esp, &(uint32_t){HOST_EXIT_THUNK}, 4);
    ST(c->r + 16, esp, 4);

    int rc = host_run_guest(c, entry);
    if (rc) return 3;
    fprintf(stderr, "[host] entry returned, EAX=%#x\n", (uint32_t)LD(c->r, 4));
    return 0;
}

// Runs guest code on this host thread with a trap guard; returns 0, or the trap code.
int host_run_guest(CPU *c, uint32_t entry) {
    jmp_buf jb;
    jmp_buf *saved = trap_jb;
    trap_jb = &jb;
    if (setjmp(jb)) {
        fprintf(stderr, "[host] TRAP (thread %u): %s at %#x (EIP~%#x)\n", G32(REG(c, 272) + 0x24),
                trap_name(trap_code), trap_addr, (uint32_t)LD(c->r + 644, 4));
        rt_calltrace_dump();
        trap_jb = saved;
        return trap_code;
    }
    rt_call(c, entry);
    trap_jb = saved;
    return 0;
}
