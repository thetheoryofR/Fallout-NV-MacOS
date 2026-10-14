#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include "com.h"
static pthread_mutex_t tl = PTHREAD_MUTEX_INITIALIZER;

uint32_t host_thunk(const char *name, ShimFn fn) {
    pthread_mutex_lock(&tl);
    if (host_import_count >= MAX_IMPORTS) { fprintf(stderr, "[com] out of thunks\n"); abort(); }
    HostImport *hi = &host_imports[host_import_count];
    snprintf(hi->dll, sizeof hi->dll, "com");
    snprintf(hi->name, sizeof hi->name, "%s", name);
    hi->fn = fn;
    uint32_t r = IMPORT_THUNK_BASE + 4u * (uint32_t)host_import_count++;
    pthread_mutex_unlock(&tl);
    return r;
}

// unimplemented COM method: name it and stop (same contract as an unimplemented import)
static _Thread_local const char *missing_name;
static void com_missing(CPU *c) {
    // find our own name from the thunk table entry that dispatched here
    fprintf(stderr, "[com] unimplemented method called (see last [imp] trace line)\n");
    rt_trap(c, 8 /* TRAP_IMPORT */, 0);
}

uint32_t com_vtable(const char *iface, const ComMethod *m, int n) {
    uint32_t vt = gmalloc(4u * (uint32_t)n);
    for (int i = 0; i < n; i++) {
        char nm[96];
        snprintf(nm, sizeof nm, "%s::%s", iface, m[i].name ? m[i].name : "?");
        P32(vt + 4u * (uint32_t)i, host_thunk(nm, m[i].fn ? m[i].fn : com_missing));
    }
    (void)missing_name;
    return vt;
}

uint32_t com_new(uint32_t vtable, uint32_t extra) {
    uint32_t o = gmalloc(12 + extra);
    P32(o, vtable); P32(o + 4, 1);
    return o;
}

void com_AddRef(CPU *c) { uint32_t o = COM_THIS(c); P32(o + 4, G32(o + 4) + 1); RET(c, G32(o + 4), 1); }
void com_Release(CPU *c) { uint32_t o = COM_THIS(c); uint32_t r = G32(o + 4); if (r) r--; P32(o + 4, r); RET(c, r, 1); }
