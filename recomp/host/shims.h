#pragma once
#include "host.h"

typedef struct { const char *name; ShimFn fn; } Shim;
typedef struct { const Shim *list; int count; } ShimTable;
#define SHIM(n) static void n##_(CPU *c)
#define E(n) { #n, n##_ },
#define SHIM_TABLE(var, ...) static const Shim var##_list[] = { __VA_ARGS__ }; \
    const ShimTable var = { var##_list, (int)(sizeof var##_list / sizeof *var##_list) };

extern _Thread_local uint32_t host_last_error;
#define SETERR(e) (host_last_error = (e))

// Windows path -> host path (backslashes, drive letters, the game root)
void host_path(const char *win, char *out, size_t n);
// UTF-16 guest string helpers
void w2a(uint32_t w, char *out, size_t n);
uint32_t wlen(uint32_t w);

// handles
enum { H_FILE = 1, H_FIND, H_EVENT, H_SEMA, H_MUTEX, H_THREAD };
uint32_t handle_new(int type, void *obj);
void *handle_get(uint32_t h, int type);
int handle_type(uint32_t h);
void handle_close(uint32_t h);
