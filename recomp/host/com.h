#pragma once
#include "shims.h"

// A guest COM object: [vtable ptr][refcount][host-side id][user data ...]. Its vtable lives in guest
// memory and holds import-thunk addresses, so the recompiled game's `call [vtbl+N]` lands in native
// code exactly like a call to a Windows import.
typedef struct { const char *name; ShimFn fn; int nargs; } ComMethod;   // nargs excludes `this`

uint32_t host_thunk(const char *name, ShimFn fn);
uint32_t com_vtable(const char *iface, const ComMethod *m, int n);      // build once per interface
uint32_t com_new(uint32_t vtable, uint32_t extra_bytes);                // allocate an instance
#define COM_THIS(c) ARG(c, 0)
#define COM_DATA(obj) ((obj) + 12)

// generic IUnknown pieces
void com_AddRef(CPU *c);
void com_Release(CPU *c);
// a method that just returns S_OK / a value with nargs popped (for null/headless backends)
#define COM_STUB_OK(fname, n) static void fname(CPU *c) { RET(c, 0, (n) + 1); }
