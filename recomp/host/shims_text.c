// Text, locale, time, system info and the remaining small kernel32 entry points.
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>
#include "shims.h"

// code page 1252 is treated as Latin-1 (identical for the ASCII the engine uses)
SHIM(MultiByteToWideChar) {
    uint32_t src = ARG(c, 2); int32_t n = (int32_t)ARG(c, 3); uint32_t dst = ARG(c, 4); int32_t cap = (int32_t)ARG(c, 5);
    if (n < 0) n = (int32_t)strlen((char *)MEM + src) + 1;
    if (!cap) { RET(c, (uint32_t)n, 6); return; }
    int32_t k = n < cap ? n : cap;
    for (int32_t i = 0; i < k; i++) { uint16_t ch = MEM[src + i]; memcpy(MEM + dst + 2 * i, &ch, 2); }
    RET(c, (uint32_t)k, 6);
}
SHIM(WideCharToMultiByte) {
    uint32_t src = ARG(c, 2); int32_t n = (int32_t)ARG(c, 3); uint32_t dst = ARG(c, 4); int32_t cap = (int32_t)ARG(c, 5);
    if (n < 0) n = (int32_t)wlen(src) + 1;
    if (!cap) { RET(c, (uint32_t)n, 8); return; }
    int32_t k = n < cap ? n : cap;
    for (int32_t i = 0; i < k; i++) { uint16_t ch; memcpy(&ch, MEM + src + 2 * i, 2); MEM[dst + i] = ch < 256 ? (uint8_t)ch : '?'; }
    RET(c, (uint32_t)k, 8);
}
SHIM(lstrcatA) { strcat((char *)MEM + ARG(c, 0), (char *)MEM + ARG(c, 1)); RET(c, ARG(c, 0), 2); }
SHIM(lstrcpyA) { strcpy((char *)MEM + ARG(c, 0), (char *)MEM + ARG(c, 1)); RET(c, ARG(c, 0), 2); }

// LCMapString: only case mapping matters to the CRT (tolower/toupper tables)
SHIM(LCMapStringA) {
    uint32_t fl = ARG(c, 1), src = ARG(c, 2); int32_t n = (int32_t)ARG(c, 3); uint32_t dst = ARG(c, 4); int32_t cap = (int32_t)ARG(c, 5);
    if (n < 0) n = (int32_t)strlen((char *)MEM + src) + 1;
    if (!cap) { RET(c, (uint32_t)n, 6); return; }
    for (int32_t i = 0; i < n && i < cap; i++) { int ch = MEM[src + i]; MEM[dst + i] = (uint8_t)(fl & 0x100 ? tolower(ch) : fl & 0x200 ? toupper(ch) : ch); }
    RET(c, (uint32_t)(n < cap ? n : cap), 6);
}
SHIM(LCMapStringW) {
    uint32_t fl = ARG(c, 1), src = ARG(c, 2); int32_t n = (int32_t)ARG(c, 3); uint32_t dst = ARG(c, 4); int32_t cap = (int32_t)ARG(c, 5);
    if (n < 0) n = (int32_t)wlen(src) + 1;
    if (!cap) { RET(c, (uint32_t)n, 6); return; }
    for (int32_t i = 0; i < n && i < cap; i++) {
        uint16_t ch; memcpy(&ch, MEM + src + 2 * i, 2);
        if (ch < 128) ch = (uint16_t)(fl & 0x100 ? tolower(ch) : fl & 0x200 ? toupper(ch) : ch);
        memcpy(MEM + dst + 2 * i, &ch, 2);
    }
    RET(c, (uint32_t)(n < cap ? n : cap), 6);
}
SHIM(CompareStringA) {
    uint32_t fl = ARG(c, 1); const char *a = (char *)MEM + ARG(c, 2), *b = (char *)MEM + ARG(c, 4);
    int32_t na = (int32_t)ARG(c, 3), nb = (int32_t)ARG(c, 5);
    if (na < 0) na = (int32_t)strlen(a); if (nb < 0) nb = (int32_t)strlen(b);
    int r = (fl & 1) ? strncasecmp(a, b, (size_t)(na < nb ? na : nb)) : strncmp(a, b, (size_t)(na < nb ? na : nb));
    if (!r) r = na - nb;
    RET(c, r < 0 ? 1 : r > 0 ? 3 : 2, 6);
}
SHIM(CompareStringW) {
    uint32_t a = ARG(c, 2), b = ARG(c, 4); int32_t na = (int32_t)ARG(c, 3), nb = (int32_t)ARG(c, 5);
    if (na < 0) na = (int32_t)wlen(a); if (nb < 0) nb = (int32_t)wlen(b);
    int r = 0;
    for (int32_t i = 0; !r && i < na && i < nb; i++) { uint16_t x, y; memcpy(&x, MEM + a + 2 * i, 2); memcpy(&y, MEM + b + 2 * i, 2); r = (int)x - (int)y; }
    if (!r) r = na - nb;
    RET(c, r < 0 ? 1 : r > 0 ? 3 : 2, 6);
}
// GetStringType: C1_* classification used to build the CRT ctype table
static uint16_t ctype1(int ch) {
    uint16_t t = 0;
    if (ch >= 'A' && ch <= 'Z') t |= 0x1 | 0x100;      // UPPER | ALPHA
    if (ch >= 'a' && ch <= 'z') t |= 0x2 | 0x100;      // LOWER | ALPHA
    if (ch >= '0' && ch <= '9') t |= 0x4;              // DIGIT
    if (ch == ' ' || (ch >= 9 && ch <= 13)) t |= 0x8;  // SPACE
    if (ch == ' ') t |= 0x40;                          // BLANK
    if (ch == '\t') t |= 0x40;
    if (ispunct(ch)) t |= 0x10;                        // PUNCT
    if (ch < 32 || ch == 127) t |= 0x20;               // CNTRL
    if (isxdigit(ch)) t |= 0x80;                       // XDIGIT
    return t;
}
SHIM(GetStringTypeA) {
    uint32_t src = ARG(c, 2); int32_t n = (int32_t)ARG(c, 3); uint32_t out = ARG(c, 4);
    if (n < 0) n = (int32_t)strlen((char *)MEM + src) + 1;
    for (int32_t i = 0; i < n; i++) { uint16_t t = ctype1(MEM[src + i]); memcpy(MEM + out + 2 * i, &t, 2); }
    RET(c, 1, 5);
}
SHIM(GetStringTypeW) {
    uint32_t src = ARG(c, 1); int32_t n = (int32_t)ARG(c, 2); uint32_t out = ARG(c, 3);
    if (n < 0) n = (int32_t)wlen(src) + 1;
    for (int32_t i = 0; i < n; i++) { uint16_t ch; memcpy(&ch, MEM + src + 2 * i, 2); uint16_t t = ch < 128 ? ctype1(ch) : 0x100; memcpy(MEM + out + 2 * i, &t, 2); }
    RET(c, 1, 4);
}
SHIM(GetUserDefaultLCID) { RET(c, 0x409, 0); }
SHIM(IsValidLocale) { RET(c, 1, 2); }
SHIM(EnumSystemLocalesA) { RET(c, 1, 2); }
SHIM(GetLocaleInfoA) {
    uint32_t type = ARG(c, 1) & 0xFFFF, buf = ARG(c, 2), n = ARG(c, 3);
    const char *v = type == 0x1004 ? "1252" : type == 0xB ? "437" : type == 0xE ? "." : type == 0xF ? "," : "";
    uint32_t l = (uint32_t)strlen(v) + 1;
    if (n) { if (n < l) l = n; memcpy(MEM + buf, v, l - 1); MEM[buf + l - 1] = 0; }
    RET(c, l, 4);
}
SHIM(GetLocaleInfoW) {
    uint32_t type = ARG(c, 1) & 0xFFFF, buf = ARG(c, 2), n = ARG(c, 3);
    const char *v = type == 0x1004 ? "1252" : type == 0xB ? "437" : "";
    uint32_t l = (uint32_t)strlen(v) + 1;
    if (n) { for (uint32_t i = 0; i < l && i < n; i++) { uint16_t ch = (uint8_t)v[i]; memcpy(MEM + buf + 2 * i, &ch, 2); } }
    RET(c, l, 4);
}
SHIM(GetConsoleCP) { RET(c, 437, 0); }
SHIM(GetConsoleOutputCP) { RET(c, 437, 0); }
SHIM(GetConsoleMode) { RET(c, 0, 2); }
SHIM(WriteConsoleA) { fwrite(MEM + ARG(c, 1), 1, ARG(c, 2), stderr); if (ARG(c, 3)) P32(ARG(c, 3), ARG(c, 2)); RET(c, 1, 5); }
SHIM(WriteConsoleW) { for (uint32_t i = 0; i < ARG(c, 2); i++) fputc(MEM[ARG(c, 1) + 2 * i], stderr); if (ARG(c, 3)) P32(ARG(c, 3), ARG(c, 2)); RET(c, 1, 5); }
SHIM(SetStdHandle) { RET(c, 1, 2); }
SHIM(SetEnvironmentVariableA) { RET(c, 1, 2); }

// ---- time --------------------------------------------------------------------------------------
static void put_systemtime(uint32_t p, struct tm *t, int ms) {
    uint16_t v[8] = {(uint16_t)(t->tm_year + 1900), (uint16_t)(t->tm_mon + 1), (uint16_t)t->tm_wday, (uint16_t)t->tm_mday,
                     (uint16_t)t->tm_hour, (uint16_t)t->tm_min, (uint16_t)t->tm_sec, (uint16_t)ms};
    memcpy(MEM + p, v, 16);
}
SHIM(GetLocalTime) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); struct tm t; localtime_r(&ts.tv_sec, &t); put_systemtime(ARG(c, 0), &t, (int)(ts.tv_nsec / 1000000)); RET(c, 0, 1); }
SHIM(GetSystemTime) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); struct tm t; gmtime_r(&ts.tv_sec, &t); put_systemtime(ARG(c, 0), &t, (int)(ts.tv_nsec / 1000000)); RET(c, 0, 1); }
SHIM(FileTimeToSystemTime) {
    uint64_t ft; memcpy(&ft, MEM + ARG(c, 0), 8);
    time_t s = (time_t)(ft / 10000000ull - 11644473600ull); struct tm t; gmtime_r(&s, &t);
    put_systemtime(ARG(c, 1), &t, (int)((ft / 10000) % 1000)); RET(c, 1, 2);
}
SHIM(FileTimeToLocalFileTime) {
    uint64_t ft; memcpy(&ft, MEM + ARG(c, 0), 8);
    time_t s = (time_t)(ft / 10000000ull - 11644473600ull); struct tm t; localtime_r(&s, &t);
    ft += (uint64_t)((int64_t)t.tm_gmtoff * 10000000ll); memcpy(MEM + ARG(c, 1), &ft, 8); RET(c, 1, 2);
}
SHIM(SystemTimeToTzSpecificLocalTime) { memcpy(MEM + ARG(c, 2), MEM + ARG(c, 1), 16); RET(c, 1, 3); }
SHIM(GetTimeZoneInformation) { memset(MEM + ARG(c, 0), 0, 172); RET(c, 0, 1); }

// ---- system ----------------------------------------------------------------------------------
SHIM(GetSystemInfo) {
    uint32_t p = ARG(c, 0); memset(MEM + p, 0, 36);
    P32(p + 4, 4096); P32(p + 8, 0x10000); P32(p + 12, 0x7FFEFFFF); P32(p + 16, 0xFF);
    P32(p + 20, 8);            // processors visible to the game (it sizes its job threads from this)
    P32(p + 24, 586); P32(p + 28, 0x10000); MEM[p + 32] = 6;
    RET(c, 0, 1);
}
SHIM(GlobalMemoryStatus) {
    uint32_t p = ARG(c, 0); P32(p, 32); P32(p + 4, 30);
    P32(p + 8, 0x7FFFFFFF); P32(p + 12, 0x7FFFFFFF); P32(p + 16, 0x7FFFFFFF); P32(p + 20, 0x7FFFFFFF);
    P32(p + 24, 0xFFFE0000u); P32(p + 28, 0xC0000000u); RET(c, 0, 1);
}
SHIM(GlobalMemoryStatusEx) {
    uint32_t p = ARG(c, 0); uint64_t big = 16ull << 30, va = 4ull << 30, avail = 3ull << 30;
    P32(p + 4, 30); memcpy(MEM + p + 8, &big, 8); memcpy(MEM + p + 16, &big, 8); memcpy(MEM + p + 24, &big, 8);
    memcpy(MEM + p + 32, &big, 8); memcpy(MEM + p + 40, &va, 8); memcpy(MEM + p + 48, &avail, 8); memset(MEM + p + 56, 0, 8);
    RET(c, 1, 1);
}
SHIM(LocalFree) { gfree(ARG(c, 0)); RET(c, 0, 1); }
SHIM(FormatMessageA) { uint32_t buf = ARG(c, 4); if (!(ARG(c, 0) & 0x100) && buf) { strcpy((char *)MEM + buf, "error"); } RET(c, 5, 7); }
SHIM(DebugBreak) { fprintf(stderr, "[host] DebugBreak\n"); RET(c, 0, 0); }
SHIM(RaiseException) {
    if (ARG(c, 0) == 0x406D1388u) {        // MS_VC_EXCEPTION: "set thread name" for a debugger
        uint32_t info = ARG(c, 3);         // THREADNAME_INFO {type, name*, threadId, flags}
        if (info && G32(info) == 0x1000 && G32(info + 4)) fprintf(stderr, "[host] thread %#x named \"%s\"\n", G32(info + 8), GSTR(G32(info + 4)));
        RET(c, 0, 4);                      // no debugger attached: the guest's __except swallows it
        return;
    }
    fprintf(stderr, "[host] RaiseException(code=%#x, flags=%#x, nargs=%u) — SEH dispatch not implemented yet\n", ARG(c, 0), ARG(c, 1), ARG(c, 2));
    rt_trap(c, TRAP_UNSUPPORTED, ARG(c, 0));
}
SHIM(RtlUnwind) { fprintf(stderr, "[host] RtlUnwind — not implemented yet\n"); rt_trap(c, TRAP_UNSUPPORTED, 0); }
SHIM(TerminateProcess) {
    fprintf(stderr, "[host] TerminateProcess(%#x) — guest stack (code-looking words):\n", ARG(c, 1));
    uint32_t sp = REG(c, R_ESP);
    for (int i = 0, shown = 0; i < 1024 && shown < 24; i++) {
        uint32_t v = G32(sp + 4 * (uint32_t)i);
        if (v >= 0x401000 && v < 0xfdf000) { fprintf(stderr, "  [esp+%#x] %#x\n", 4 * i, v); shown++; }
    }
    rt_calltrace_dump();
    exit((int)ARG(c, 1));
}

SHIM_TABLE(text_shims,
    E(MultiByteToWideChar) E(WideCharToMultiByte) E(lstrcatA) E(lstrcpyA) E(LCMapStringA) E(LCMapStringW)
    E(CompareStringA) E(CompareStringW) E(GetStringTypeA) E(GetStringTypeW) E(GetUserDefaultLCID)
    E(IsValidLocale) E(EnumSystemLocalesA) E(GetLocaleInfoA) E(GetLocaleInfoW) E(GetConsoleCP)
    E(GetConsoleOutputCP) E(GetConsoleMode) E(WriteConsoleA) E(WriteConsoleW) E(SetStdHandle)
    E(SetEnvironmentVariableA) E(GetLocalTime) E(GetSystemTime) E(FileTimeToSystemTime)
    E(FileTimeToLocalFileTime) E(SystemTimeToTzSpecificLocalTime) E(GetTimeZoneInformation) E(GetSystemInfo)
    E(GlobalMemoryStatus) E(GlobalMemoryStatusEx) E(LocalFree) E(FormatMessageA) E(DebugBreak)
    E(RaiseException) E(RtlUnwind) E(TerminateProcess))
