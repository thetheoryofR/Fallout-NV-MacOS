// x86 fallback interpreter. When dispatch finds no native function for a guest address (code that
// static analysis missed, or code a plugin patched at runtime), the call runs in Unicorn instead,
// on the SAME guest memory. Inside it, import thunks go to the native shims and calls into known
// native functions jump back out to native code. Every fallback root is logged so the next
// analysis pass can make it native.
#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include "host.h"

extern int rt_has_fn(uint32_t a);
#define MAXDEPTH 32
static _Thread_local uc_engine *engines[MAXDEPTH];
static _Thread_local int depth;
static _Thread_local CPU *cur_cpu[MAXDEPTH];
static _Thread_local uint32_t cur_root[MAXDEPTH];

// Ghidra register-file offsets
#define O_EFL_CF 512
#define O_ST0 4352
#define O_XMM0 4608
#define O_FPUCW 4256
#define O_C0 4240
static const int gpr_uc[8] = {UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
                              UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI};
static const struct { int off, bit; } flag_bits[] = {{512, 0}, {514, 2}, {516, 4}, {518, 6}, {519, 7}, {522, 10}, {523, 11}};

static void cpu_to_uc(CPU *c, uc_engine *uc) {
    for (int i = 0; i < 8; i++) { uint32_t v = REG(c, 4 * i); uc_reg_write(uc, gpr_uc[i], &v); }
    uint32_t efl = 2;
    for (size_t i = 0; i < sizeof flag_bits / sizeof *flag_bits; i++) efl |= (uint32_t)(c->r[flag_bits[i].off] & 1) << flag_bits[i].bit;
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &efl);
    uint32_t top = c->r[REG_TOP] & 7;
    for (int i = 0; i < 8; i++) {
        uint8_t f[16] = {0}; double d; memcpy(&d, c->r + O_ST0 + 16 * i, 8); f80_put(f, d);   // double -> 80-bit
        uc_reg_write(uc, UC_X86_REG_FP0 + (int)((top + (uint32_t)i) & 7), f);
    }
    uint32_t sw = (top << 11) | ((uint32_t)(c->r[O_C0] & 1) << 8) | ((uint32_t)(c->r[O_C0 + 1] & 1) << 9) |
                  ((uint32_t)(c->r[O_C0 + 2] & 1) << 10) | ((uint32_t)(c->r[O_C0 + 3] & 1) << 14);
    uint32_t cw = (uint32_t)LD(c->r + O_FPUCW, 2), tag = 0;
    uc_reg_write(uc, UC_X86_REG_FPSW, &sw); uc_reg_write(uc, UC_X86_REG_FPCW, &cw); uc_reg_write(uc, UC_X86_REG_FPTAG, &tag);
    for (int i = 0; i < 8; i++) { uint64_t x[2]; memcpy(x, c->r + O_XMM0 + 64 * i, 16); uc_reg_write(uc, UC_X86_REG_XMM0 + i, x); }
}

static void uc_to_cpu(uc_engine *uc, CPU *c) {
    for (int i = 0; i < 8; i++) { uint32_t v; uc_reg_read(uc, gpr_uc[i], &v); SETREG(c, 4 * i, v); }
    uint32_t efl; uc_reg_read(uc, UC_X86_REG_EFLAGS, &efl);
    for (size_t i = 0; i < sizeof flag_bits / sizeof *flag_bits; i++) c->r[flag_bits[i].off] = (efl >> flag_bits[i].bit) & 1;
    uint32_t sw; uc_reg_read(uc, UC_X86_REG_FPSW, &sw);
    uint32_t top = (sw >> 11) & 7;
    c->r[REG_TOP] = (uint8_t)top;
    c->r[O_C0] = (sw >> 8) & 1; c->r[O_C0 + 1] = (sw >> 9) & 1; c->r[O_C0 + 2] = (sw >> 10) & 1; c->r[O_C0 + 3] = (sw >> 14) & 1;
    for (int i = 0; i < 8; i++) {
        uint8_t f[16] = {0}; uc_reg_read(uc, UC_X86_REG_FP0 + (int)((top + (uint32_t)i) & 7), f);
        double d = f80_get(f); memcpy(c->r + O_ST0 + 16 * i, &d, 8);
    }
    for (int i = 0; i < 8; i++) { uint64_t x[2]; uc_reg_read(uc, UC_X86_REG_XMM0 + i, x); memcpy(c->r + O_XMM0 + 64 * i, x, 16); }
}

// block hook: import thunks -> native shims; known native entries -> native code
static _Thread_local uint32_t prev_end[MAXDEPTH];   // end address of the previous block, per engine

static void on_block(uc_engine *uc, uint64_t address, uint32_t size, void *user) {
    (void)user;
    int d = depth - 1;
    CPU *c = cur_cpu[d];
    uint32_t a = (uint32_t)address;
    uint32_t came_from = prev_end[d];
    prev_end[d] = a + size;
    int is_import = a >= IMPORT_THUNK_BASE && a < IMPORT_THUNK_BASE + 0x10000;
    if (!is_import && (a == cur_root[d] || !rt_has_fn(a))) return;
    uint32_t esp; uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret = G32(esp);
    // Hand off to native code only when this block was entered by a CALL: then [ESP] is the
    // address right after the calling block. A jump or fall-through into a native entry keeps
    // interpreting (always correct, just slower) — treating it as a call would "return" to
    // whatever value happens to sit on top of the stack.
    if (!is_import && ret != came_from) return;
    uc_to_cpu(uc, c);
    if (is_import) rt_import_call(c, a);
    else rt_call(c, a);                     // may itself fall back (nested engine)
    cpu_to_uc(c, uc);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret);
}

static uc_engine *engine(CPU *c) {
    if (engines[depth]) return engines[depth];
    uc_engine *uc;
    if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) { fprintf(stderr, "[fallback] uc_open failed\n"); abort(); }
    uc_err e = uc_mem_map_ptr(uc, 0, (size_t)1 << 32, UC_PROT_ALL, MEM);
    if (e != UC_ERR_OK) { fprintf(stderr, "[fallback] map: %s\n", uc_strerror(e)); abort(); }
    // GDT: flat 32-bit code/data + FS -> this thread's TEB (stored just past the TEB page)
    uint32_t teb = REG(c, 272), gdt = teb + 0x1F00;
    uint8_t table[32] = {0};
    uint8_t code[8] = {0xFF, 0xFF, 0, 0, 0, 0x9B, 0xCF, 0}, data[8] = {0xFF, 0xFF, 0, 0, 0, 0x93, 0xCF, 0};
    uint8_t fs[8] = {0xFF, 0x0F, (uint8_t)teb, (uint8_t)(teb >> 8), (uint8_t)(teb >> 16), 0x93, 0x40, (uint8_t)(teb >> 24)};
    memcpy(table + 8, code, 8); memcpy(table + 16, data, 8); memcpy(table + 24, fs, 8);
    memcpy(MEM + gdt, table, 32);
    uc_x86_mmr g = {0, gdt, 31, 0};
    uc_reg_write(uc, UC_X86_REG_GDTR, &g);
    uint32_t sel = 1 << 3; uc_reg_write(uc, UC_X86_REG_CS, &sel);
    sel = 2 << 3; uc_reg_write(uc, UC_X86_REG_SS, &sel); uc_reg_write(uc, UC_X86_REG_DS, &sel); uc_reg_write(uc, UC_X86_REG_ES, &sel);
    sel = 3 << 3; uc_reg_write(uc, UC_X86_REG_FS, &sel);
    uc_hook h; uc_hook_add(uc, &h, UC_HOOK_BLOCK, (void *)on_block, NULL, 1, 0);
    engines[depth] = uc;
    return uc;
}

static void log_root(uint32_t a) {
    static uint32_t seen[65536]; static int n;
    for (int i = 0; i < n; i++) if (seen[i] == a) return;
    if (n < 65536) seen[n++] = a;
    FILE *f = fopen("fallback_entries.txt", "a");
    if (f) { fprintf(f, "%#x\n", a); fclose(f); }
    if (getenv("FNV_TRACE")) fprintf(stderr, "[fallback] interpreting %#x\n", a);
}

void rt_fallback(CPU *c, uint32_t a) {
    if (a < 0x401000 || a >= 0x1000000 || depth >= MAXDEPTH) rt_trap(c, TRAP_NOFN, a);   // only .text
    log_root(a);
    uc_engine *uc = engine(c);
    cur_cpu[depth] = c; cur_root[depth] = a; prev_end[depth] = 0;
    depth++;
    uint32_t ret = G32(REG(c, R_ESP));      // the CALL already pushed it
    cpu_to_uc(c, uc);
    uc_err e = uc_emu_start(uc, a, ret, 0, 0);
    depth--;
    if (e != UC_ERR_OK) {
        uint32_t eip; uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        fprintf(stderr, "[fallback] %s at %#x (root %#x)\n", uc_strerror(e), eip, a);
        rt_trap(c, TRAP_NOFN, eip);
    }
    uc_to_cpu(uc, c);
    // emulate the RET that brought us to `ret`: Unicorn stopped *at* ret with ESP already popped
}
