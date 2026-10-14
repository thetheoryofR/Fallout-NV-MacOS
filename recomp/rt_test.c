// Test-harness runtime: owns the 4 GB guest space and runs one recompiled function with a trap
// guard, so difftest.py can drive it through ctypes.
#include <setjmp.h>
#include <sys/mman.h>
#include "rt.h"

#ifndef RT_FIXED_MEM
uint8_t *MEM;
#endif
int64_t rt_budget;
static jmp_buf trap_jb;
static int trap_code;
static uint32_t trap_addr;

extern const uint32_t rt_fn_addr[];
extern const GuestFn rt_fn_ptr[];
extern const int rt_fn_count;

void rt_trap(CPU *c, int code, uint32_t addr) {
    (void)c;
    trap_code = code;
    trap_addr = addr;
    longjmp(trap_jb, 1);
}

uint8_t *rt_mem(void) {
#ifdef RT_FIXED_MEM
    static uint8_t *m;
    if (!m) {
        void *p = mmap((void *)RT_MEM_BASE, (size_t)1 << 32, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        m = p == (void *)RT_MEM_BASE ? (uint8_t *)p : NULL;
    }
    return m;
#else
    if (!MEM) {
        void *p = mmap(NULL, (size_t)1 << 32, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        MEM = p == MAP_FAILED ? NULL : (uint8_t *)p;
    }
    return MEM;
#endif
}
int rt_count(void) { return rt_fn_count; }
uint32_t rt_addr(int i) { return rt_fn_addr[i]; }
uint32_t rt_trap_addr(void) { return trap_addr; }

// Returns 0 on normal return, else the trap code.
int rt_run(int i, CPU *c, int64_t budget) {
    rt_budget = budget;
    if (setjmp(trap_jb)) return trap_code;
    rt_fn_ptr[i](c);
    return 0;
}
