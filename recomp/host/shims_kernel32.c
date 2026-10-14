// kernel32 (and friends) shims, grown one trap at a time. Each shim reads its arguments from the
// guest stack, does the work natively, sets EAX and pops like the real stdcall export.
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "host.h"

const char *host_saved_cmdline;
_Thread_local uint32_t host_last_error;
#define last_error host_last_error
static uint32_t cmdline_a, cmdline_w;
static uint32_t teb_main;

void host_init_args(int argc, char **argv) {
    char buf[4096] = "FalloutNV.exe";
    for (int i = 1; i < argc; i++) { strncat(buf, " ", sizeof buf - strlen(buf) - 1); strncat(buf, argv[i], sizeof buf - strlen(buf) - 1); }
    (void)argc;
    // allocated lazily (heap needs MEM); stash in a static until first use
    static char saved[4096];
    memcpy(saved, buf, sizeof saved);
    cmdline_a = 0;
    host_saved_cmdline = saved;
}

// ---- thread / TEB ----------------------------------------------------------------------------
#define TLS_SLOTS 64
void host_thread_init(CPU *c, uint32_t stack_size) {
    uint32_t stack = gpages(stack_size);
    uint32_t teb = gpages(0x2000);
    P32(teb + 0x00, 0xFFFFFFFFu);              // SEH chain end
    P32(teb + 0x04, stack + stack_size);       // stack top
    P32(teb + 0x08, stack);                    // stack limit
    P32(teb + 0x18, teb);                      // self
    P32(teb + 0x20, (uint32_t)getpid());       // ClientId.UniqueProcess
    P32(teb + 0x24, 1);                        // ClientId.UniqueThread (main thread)
    P32(teb + 0x2C, teb + 0x1000);             // ThreadLocalStoragePointer (static TLS array)
    P32(teb + 0x30, gpages(0x1000));           // PEB
    SETREG(c, 272, teb);                       // FS_OFFSET
    SETREG(c, R_ESP, stack + stack_size - 64);
    if (!teb_main) teb_main = teb;
}

// ---- shims -----------------------------------------------------------------------------------
#define SHIM(n) static void n(CPU *c)

SHIM(GetLastError_) { RET(c, last_error, 0); }
SHIM(SetLastError_) { last_error = ARG(c, 0); RET(c, 0, 1); }
SHIM(GetVersion_) { RET(c, 0x0A280105u, 0); }            // "Windows XP SP2-ish": 5.1 build 2600
SHIM(GetVersionExA_) {
    uint32_t v = ARG(c, 0);
    P32(v + 4, 5); P32(v + 8, 1); P32(v + 12, 2600); P32(v + 16, 2);
    RET(c, 1, 1);
}
SHIM(GetCommandLineA_) {
    if (!cmdline_a) { uint32_t n = (uint32_t)strlen(host_saved_cmdline) + 1; cmdline_a = gmalloc(n); memcpy(MEM + cmdline_a, host_saved_cmdline, n); }
    RET(c, cmdline_a, 0);
}
SHIM(GetCommandLineW_) {
    if (!cmdline_w) { uint32_t n = (uint32_t)strlen(host_saved_cmdline) + 1; cmdline_w = gmalloc(2 * n);
        for (uint32_t i = 0; i < n; i++) { uint16_t ch = (uint8_t)host_saved_cmdline[i]; memcpy(MEM + cmdline_w + 2 * i, &ch, 2); } }
    RET(c, cmdline_w, 0);
}
// ---- modules: system DLLs get fake handles; GetProcAddress hands out dynamic import thunks ----
#define MOD_BASE 0xFD000000u
static const char *known_mods[] = {"kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32",
    "ntdll", "d3d9", "dinput8", "dsound", "xinput1_3", "winmm", "comctl32", "wsock32", "d3dx9_38",
    "binkw32", "libvorbisfile", "steam_api", "shlwapi", "version", "mscoree", "msvcrt"};
#define NMODS (sizeof known_mods / sizeof *known_mods)

static uint32_t mod_handle(const char *name) {
    if (!name) return host_image_base;
    char low[128]; size_t n = 0;
    for (const char *p = strrchr(name, '\\') ? strrchr(name, '\\') + 1 : name; *p && n < sizeof low - 1; p++)
        low[n++] = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
    low[n] = 0;
    char *dot = strstr(low, ".dll"); if (dot) *dot = 0;
    if (!strcmp(low, "falloutnv")) return host_image_base;
    for (size_t i = 0; i < NMODS; i++) if (!strcmp(low, known_mods[i])) return MOD_BASE + 0x10000u * (uint32_t)i;
    return 0;
}
static void wide_to_ascii(uint32_t w, char *out, size_t n) {
    size_t i = 0; uint16_t ch;
    for (; i < n - 1; i++) { memcpy(&ch, MEM + w + 2 * i, 2); if (!ch) break; out[i] = (char)ch; }
    out[i] = 0;
}
SHIM(GetModuleHandleA_) { uint32_t h = mod_handle(GSTR(ARG(c, 0))); if (!h) last_error = 126; RET(c, h, 1); }
SHIM(GetModuleHandleW_) {
    char nm[256]; uint32_t a = ARG(c, 0);
    if (a) wide_to_ascii(a, nm, sizeof nm);
    uint32_t h = mod_handle(a ? nm : NULL); if (!h) last_error = 126; RET(c, h, 1);
}
SHIM(LoadLibraryA_) {
    const char *nm = GSTR(ARG(c, 0)); uint32_t h = mod_handle(nm);
    fprintf(stderr, "[host] LoadLibraryA(%s) -> %#x\n", nm, h);
    if (!h) last_error = 126; RET(c, h, 1);
}
SHIM(LoadLibraryW_) {
    char nm[256]; wide_to_ascii(ARG(c, 0), nm, sizeof nm); uint32_t h = mod_handle(nm);
    fprintf(stderr, "[host] LoadLibraryW(%s) -> %#x\n", nm, h);
    if (!h) last_error = 126; RET(c, h, 1);
}
SHIM(FreeLibrary_) { RET(c, 1, 1); }
SHIM(GetProcAddress_) {
    uint32_t h = ARG(c, 0), pn = ARG(c, 1);
    char name[96];
    if (pn < 0x10000) snprintf(name, sizeof name, "#%u", pn); else snprintf(name, sizeof name, "%s", GSTR(pn));
    const char *dll = h >= MOD_BASE && (h - MOD_BASE) / 0x10000u < NMODS ? known_mods[(h - MOD_BASE) / 0x10000u] : "?";
    ShimFn fn = host_find_shim(dll, name);
    if (!fn) { fprintf(stderr, "[host] GetProcAddress(%s, %s) -> 0 (no shim)\n", dll, name); last_error = 127; RET(c, 0, 2); return; }
    for (int i = 0; i < host_import_count; i++)
        if (host_imports[i].fn == fn) { RET(c, IMPORT_THUNK_BASE + 4u * (uint32_t)i, 2); return; }
    HostImport *hi = &host_imports[host_import_count];
    snprintf(hi->dll, sizeof hi->dll, "%s", dll); snprintf(hi->name, sizeof hi->name, "%s", name); hi->fn = fn;
    RET(c, IMPORT_THUNK_BASE + 4u * (uint32_t)host_import_count++, 2);
}
SHIM(GetModuleFileNameA_) {
    uint32_t buf = ARG(c, 1), n = ARG(c, 2);
    const char *name = "C:\\Games\\FalloutNV\\FalloutNV.exe";
    uint32_t l = (uint32_t)strlen(name);
    if (l >= n) l = n - 1;
    memcpy(MEM + buf, name, l); MEM[buf + l] = 0;
    RET(c, l, 3);
}
SHIM(GetCurrentProcess_) { RET(c, 0xFFFFFFFFu, 0); }
SHIM(GetCurrentThread_) { RET(c, 0xFFFFFFFEu, 0); }
SHIM(GetCurrentProcessId_) { RET(c, (uint32_t)getpid(), 0); }
SHIM(GetCurrentThreadId_) { RET(c, G32(REG(c, 272) + 0x24) ? G32(REG(c, 272) + 0x24) : 1, 0); }
SHIM(GetTickCount_) { RET(c, (uint32_t)(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ull), 0); }
SHIM(QueryPerformanceCounter_) {
    uint64_t t = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    memcpy(MEM + ARG(c, 0), &t, 8); RET(c, 1, 1);
}
SHIM(QueryPerformanceFrequency_) { uint64_t f = 1000000000ull; memcpy(MEM + ARG(c, 0), &f, 8); RET(c, 1, 1); }
SHIM(GetSystemTimeAsFileTime_) {
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t ft = ((uint64_t)tv.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)tv.tv_usec * 10;
    memcpy(MEM + ARG(c, 0), &ft, 8); RET(c, 0, 1);
}
SHIM(IsProcessorFeaturePresent_) { uint32_t f = ARG(c, 0); RET(c, f == 6 || f == 7 || f == 10 || f == 13, 1); } // SSE/SSE2/3DNow!-no/SSE3
SHIM(IsDebuggerPresent_) { RET(c, 0, 0); }

// heaps: one guest heap backs all of them
SHIM(HeapCreate_) { RET(c, 0x00F00000u, 3); }
SHIM(GetProcessHeap_) { RET(c, 0x00F00000u, 0); }
SHIM(HeapDestroy_) { RET(c, 1, 1); }
SHIM(HeapAlloc_) { uint32_t f = ARG(c, 1), n = ARG(c, 2); uint32_t p = gmalloc(n); (void)f; RET(c, p, 3); }
SHIM(HeapFree_) { gfree(ARG(c, 2)); RET(c, 1, 3); }
SHIM(HeapReAlloc_) { RET(c, grealloc(ARG(c, 2), ARG(c, 3)), 4); }
SHIM(HeapSize_) { RET(c, gsize(ARG(c, 2)), 3); }
// VirtualAlloc keeps a list of reserved ranges so a fixed-address reservation that overlaps the
// image or an earlier reservation fails (ERROR_INVALID_ADDRESS) exactly like on Windows; the game's
// allocator probes fixed addresses and falls back when they are taken.
#define MAXRES 4096
static struct { uint32_t lo, hi; } res[MAXRES];
static int nres;
static int overlaps(uint32_t lo, uint32_t hi) {
    for (int i = 0; i < nres; i++) if (lo < res[i].hi && res[i].lo < hi) return i;
    return -1;
}
static void reserve(uint32_t lo, uint32_t hi) { if (nres < MAXRES) { res[nres].lo = lo; res[nres].hi = hi; nres++; } }
#include <pthread.h>
static pthread_mutex_t va_lk = PTHREAD_MUTEX_INITIALIZER;
static void VirtualAlloc_locked(CPU *c);
SHIM(VirtualAlloc_) { pthread_mutex_lock(&va_lk); VirtualAlloc_locked(c); pthread_mutex_unlock(&va_lk); }
static void VirtualAlloc_locked(CPU *c) {
    uint32_t a = ARG(c, 0), n = ARG(c, 1), type = ARG(c, 2);
    if (!nres) {    // first call: the image and the low 64 KB are taken
        reserve(0, 0x10000);
        reserve(host_image_base, host_image_base + G32(host_image_base + G32(host_image_base + 0x3C) + 24 + 56));
    }
    if (!a) { uint32_t p = gpages(n); reserve(p, p + ((n + 0xFFF) & ~0xFFFu)); RET(c, p, 4); return; }
    uint32_t lo = a & ~0xFFFu, hi = (a + n + 0xFFF) & ~0xFFFu;
    int i = overlaps(lo, hi);
    if (type & 0x2000) {                        // MEM_RESERVE at a fixed address
        if (i >= 0) { last_error = 487; RET(c, 0, 4); return; }
        reserve(lo, hi); RET(c, a, 4); return;
    }
    // MEM_COMMIT inside an existing reservation (or an untracked fixed address)
    if (i < 0) reserve(lo, hi);
    RET(c, a, 4);
}
SHIM(VirtualFree_) { RET(c, 1, 3); }
SHIM(VirtualQuery_) { RET(c, 0, 3); }

// TLS
static uint32_t tls_next;
SHIM(TlsAlloc_) { RET(c, tls_next < TLS_SLOTS ? tls_next++ : 0xFFFFFFFFu, 0); }
SHIM(TlsFree_) { RET(c, 1, 1); }
SHIM(TlsGetValue_) { uint32_t i = ARG(c, 0); last_error = 0; RET(c, G32(REG(c, 272) + 0xE10 + 4 * i), 1); }
SHIM(TlsSetValue_) { uint32_t i = ARG(c, 0); P32(REG(c, 272) + 0xE10 + 4 * i, ARG(c, 1)); RET(c, 1, 2); }

// environment / code pages / startup info
SHIM(GetEnvironmentStringsW_) { uint32_t p = gmalloc(4); RET(c, p, 0); }
SHIM(GetEnvironmentStrings_) { uint32_t p = gmalloc(2); RET(c, p, 0); }
SHIM(FreeEnvironmentStringsW_) { RET(c, 1, 1); }
SHIM(FreeEnvironmentStringsA_) { RET(c, 1, 1); }
SHIM(GetACP_) { RET(c, 1252, 0); }
SHIM(GetOEMCP_) { RET(c, 437, 0); }
SHIM(GetCPInfo_) { uint32_t p = ARG(c, 1); memset(MEM + p, 0, 20); P32(p, 1); MEM[p + 4] = '?'; RET(c, 1, 2); }
SHIM(IsValidCodePage_) { RET(c, 1, 1); }
SHIM(GetStartupInfoA_) { uint32_t p = ARG(c, 0); memset(MEM + p, 0, 68); P32(p, 68); RET(c, 0, 1); }
SHIM(GetStdHandle_) { RET(c, 0x10 + (ARG(c, 0) & 3), 1); }
SHIM(GetFileType_) { RET(c, 2, 1); }                      // FILE_TYPE_CHAR
SHIM(SetHandleCount_) { RET(c, ARG(c, 0), 1); }
SHIM(SetUnhandledExceptionFilter_) { RET(c, 0, 1); }
SHIM(UnhandledExceptionFilter_) { RET(c, 0, 1); }
SHIM(SetConsoleCtrlHandler_) { RET(c, 1, 2); }
SHIM(OutputDebugStringA_) { fprintf(stderr, "[guest] %s", GSTR(ARG(c, 0))); RET(c, 0, 1); }
SHIM(EncodePointer_) { RET(c, ARG(c, 0), 1); }
SHIM(DecodePointer_) { RET(c, ARG(c, 0), 1); }
SHIM(Sleep_) {
    uint32_t ms = ARG(c, 0);
    if (ms == 0xFFFFFFFFu) { fprintf(stderr, "[host] Sleep(INFINITE) — guest waits forever\n"); exit(4); }
    usleep((useconds_t)ms * 1000);
    RET(c, 0, 1);
}
SHIM(ExitProcess_) {
    fprintf(stderr, "[host] ExitProcess(%u) — guest stack (code-looking words):\n", ARG(c, 0));
    uint32_t sp = REG(c, R_ESP);
    for (int i = 0, shown = 0; i < 4096 && shown < 40; i++) {
        uint32_t v = G32(sp + 4 * (uint32_t)i);
        if (v >= 0x401000 && v < 0xfdf000) { fprintf(stderr, "  [esp+%#x] %#x\n", 4 * i, v); shown++; }
    }
    exit((int)ARG(c, 0));
}

typedef struct { const char *name; ShimFn fn; } Shim;
static const Shim kernel32[] = {
#define E(n) { #n, n##_ },
    E(GetLastError) E(SetLastError) E(GetVersion) E(GetVersionExA) E(GetCommandLineA) E(GetCommandLineW)
    E(GetModuleHandleA) E(GetModuleHandleW) E(GetModuleFileNameA) E(LoadLibraryA) E(LoadLibraryW)
    E(FreeLibrary) E(GetProcAddress) E(GetCurrentProcess) E(GetCurrentThread)
    E(GetCurrentProcessId) E(GetCurrentThreadId) E(GetTickCount) E(QueryPerformanceCounter)
    E(QueryPerformanceFrequency) E(GetSystemTimeAsFileTime) E(IsProcessorFeaturePresent) E(IsDebuggerPresent)
    E(HeapCreate) E(GetProcessHeap) E(HeapDestroy) E(HeapAlloc) E(HeapFree) E(HeapReAlloc) E(HeapSize)
    E(VirtualAlloc) E(VirtualFree) E(VirtualQuery) E(TlsAlloc) E(TlsFree) E(TlsGetValue) E(TlsSetValue)
    E(GetEnvironmentStringsW) E(GetEnvironmentStrings) E(FreeEnvironmentStringsW) E(FreeEnvironmentStringsA)
    E(GetACP) E(GetOEMCP) E(GetCPInfo) E(IsValidCodePage) E(GetStartupInfoA) E(GetStdHandle) E(GetFileType)
    E(SetHandleCount) E(SetUnhandledExceptionFilter) E(UnhandledExceptionFilter) E(SetConsoleCtrlHandler)
    E(OutputDebugStringA) E(Sleep) E(ExitProcess) E(EncodePointer) E(DecodePointer)
#undef E
};

typedef struct { const Shim *list; int count; } ShimTable;
extern const ShimTable sync_shims, file_shims, text_shims, win_shims, dinput_shims, dsound_shims, d3d9_shims, d3dx_shims, xinput_shims, media_shims, mmio_shims;
ShimFn host_find_shim(const char *dll, const char *name) {
    // ordinal imports collide across DLLs: look them up as "<dll basename, lowercase>#<n>"
    char key[160];
    if (name[0] == '#') {
        size_t k = 0;
        for (const char *p = dll; *p && *p != '.' && k < sizeof key - 1; p++) key[k++] = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
        key[k] = 0;
        strncat(key, name, sizeof key - strlen(key) - 1);
        name = key;
    }
    for (size_t i = 0; i < sizeof kernel32 / sizeof *kernel32; i++)
        if (!strcmp(kernel32[i].name, name)) return kernel32[i].fn;
    const ShimTable *tabs[] = {&sync_shims, &file_shims, &text_shims, &win_shims, &dinput_shims, &dsound_shims, &d3d9_shims, &d3dx_shims, &xinput_shims, &media_shims, &mmio_shims};
    for (size_t t = 0; t < sizeof tabs / sizeof *tabs; t++)
        for (int i = 0; i < tabs[t]->count; i++)
            if (!strcmp(tabs[t]->list[i].name, name)) return tabs[t]->list[i].fn;
    return NULL;
}

int host_shimmed_count(void) {
    int n = 0;
    for (int i = 0; i < host_import_count; i++) n += host_imports[i].fn != NULL;
    return n;
}
