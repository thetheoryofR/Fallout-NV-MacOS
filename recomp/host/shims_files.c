// Files, directories, find-first/next, attributes and INI profile functions.
// Windows paths map onto the host: '\' -> '/', a drive letter or the game's install path maps to
// FNV_ROOT (default: the current directory, which holds Data/ and the INIs).
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "shims.h"

void host_path(const char *win, char *out, size_t n) {
    const char *root = getenv("FNV_ROOT");
    char tmp[1024]; size_t k = 0;
    const char *p = win;
    if (p[0] && p[1] == ':') {                         // "C:\Games\FalloutNV\Data\x" -> root + rest
        p += 2;
        const char *game = strstr(p, "FalloutNV\\");
        if (game) p = game + 10;
        else if (*p == '\\') p++;
        k = (size_t)snprintf(tmp, sizeof tmp, "%s/", root ? root : ".");
    }
    for (; *p && k < sizeof tmp - 1; p++) tmp[k++] = *p == '\\' ? '/' : *p;
    tmp[k] = 0;
    snprintf(out, n, "%s", tmp);
}

void w2a(uint32_t w, char *out, size_t n) {
    size_t i = 0; uint16_t ch;
    for (; i < n - 1; i++) { memcpy(&ch, MEM + w + 2 * i, 2); if (!ch) break; out[i] = ch < 0x80 ? (char)ch : '?'; }
    out[i] = 0;
}
uint32_t wlen(uint32_t w) { uint32_t i = 0; uint16_t ch; for (;; i++) { memcpy(&ch, MEM + w + 2 * i, 2); if (!ch) return i; } }

static int trace_files(void) { static int t = -1; if (t < 0) t = getenv("FNV_TRACE_FILES") != NULL; return t; }

// ---- files -----------------------------------------------------------------------------------
typedef struct { int fd; } FileObj;

static uint32_t open_file(const char *winpath, uint32_t access, uint32_t disp) {
    char path[1024]; host_path(winpath, path, sizeof path);
    int fl = 0;
    if ((access & 0x40000000u) && (access & 0x80000000u)) fl = O_RDWR;
    else if (access & 0x40000000u) fl = O_WRONLY;
    else fl = O_RDONLY;
    switch (disp) {
    case 1: fl |= O_CREAT | O_EXCL; break;        // CREATE_NEW
    case 2: fl |= O_CREAT | O_TRUNC; break;       // CREATE_ALWAYS
    case 3: break;                                // OPEN_EXISTING
    case 4: fl |= O_CREAT; break;                 // OPEN_ALWAYS
    case 5: fl |= O_TRUNC; break;                 // TRUNCATE_EXISTING
    }
    int fd = open(path, fl, 0644);
    if (trace_files()) fprintf(stderr, "[file] open %s (%s) -> %d\n", winpath, path, fd);
    if (fd < 0) { SETERR(2); return 0xFFFFFFFFu; }   // ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE
    FileObj *f = malloc(sizeof *f); f->fd = fd;
    return handle_new(H_FILE, f);
}
SHIM(CreateFileA) { RET(c, open_file(GSTR(ARG(c, 0)), ARG(c, 1), ARG(c, 4)), 7); }
SHIM(CreateFileW) { char p[1024]; w2a(ARG(c, 0), p, sizeof p); RET(c, open_file(p, ARG(c, 1), ARG(c, 4)), 7); }
static FileObj *fobj(uint32_t h) { return handle_get(h, H_FILE); }
SHIM(ReadFile) {
    FileObj *f = fobj(ARG(c, 0)); uint32_t buf = ARG(c, 1), n = ARG(c, 2), got = ARG(c, 3);
    ssize_t r = f ? read(f->fd, MEM + buf, n) : -1;
    if (got) P32(got, r > 0 ? (uint32_t)r : 0);
    RET(c, r >= 0, 5);
}
SHIM(WriteFile) {
    uint32_t h = ARG(c, 0), buf = ARG(c, 1), n = ARG(c, 2), put = ARG(c, 3);
    ssize_t r;
    if (h >= 0x10 && h <= 0x13) r = write(2, MEM + buf, n);        // std handles -> stderr
    else { FileObj *f = fobj(h); r = f ? write(f->fd, MEM + buf, n) : -1; }
    if (put) P32(put, r > 0 ? (uint32_t)r : 0);
    RET(c, r >= 0, 5);
}
SHIM(GetFileSize) {
    FileObj *f = fobj(ARG(c, 0)); struct stat st;
    if (!f || fstat(f->fd, &st)) { RET(c, 0xFFFFFFFFu, 2); return; }
    if (ARG(c, 1)) P32(ARG(c, 1), (uint32_t)((uint64_t)st.st_size >> 32));
    RET(c, (uint32_t)st.st_size, 2);
}
SHIM(GetFileSizeEx) {
    FileObj *f = fobj(ARG(c, 0)); struct stat st;
    if (!f || fstat(f->fd, &st)) { RET(c, 0, 2); return; }
    uint64_t sz = (uint64_t)st.st_size; memcpy(MEM + ARG(c, 1), &sz, 8);
    RET(c, 1, 2);
}
SHIM(SetFilePointer) {
    FileObj *f = fobj(ARG(c, 0)); int64_t d = (int32_t)ARG(c, 1);
    if (ARG(c, 2)) d = (int64_t)(((uint64_t)G32(ARG(c, 2)) << 32) | (uint32_t)ARG(c, 1));
    off_t r = f ? lseek(f->fd, d, (int)ARG(c, 3)) : -1;
    if (ARG(c, 2) && r >= 0) P32(ARG(c, 2), (uint32_t)((uint64_t)r >> 32));
    RET(c, r < 0 ? 0xFFFFFFFFu : (uint32_t)r, 4);
}
SHIM(SetFilePointerEx) {
    FileObj *f = fobj(ARG(c, 0));
    int64_t d = (int64_t)(((uint64_t)ARG(c, 2) << 32) | ARG(c, 1));
    off_t r = f ? lseek(f->fd, d, (int)ARG(c, 4)) : -1;
    if (ARG(c, 3) && r >= 0) { uint64_t v = (uint64_t)r; memcpy(MEM + ARG(c, 3), &v, 8); }
    RET(c, r >= 0, 5);
}
SHIM(SetEndOfFile) { FileObj *f = fobj(ARG(c, 0)); RET(c, f && ftruncate(f->fd, lseek(f->fd, 0, SEEK_CUR)) == 0, 1); }
SHIM(FlushFileBuffers) { RET(c, 1, 1); }
SHIM(DeleteFileA) { char p[1024]; host_path(GSTR(ARG(c, 0)), p, sizeof p); RET(c, unlink(p) == 0, 1); }
SHIM(MoveFileA) { char a[1024], b[1024]; host_path(GSTR(ARG(c, 0)), a, sizeof a); host_path(GSTR(ARG(c, 1)), b, sizeof b); RET(c, rename(a, b) == 0, 2); }
SHIM(CopyFileA) {
    char a[1024], b[1024]; host_path(GSTR(ARG(c, 0)), a, sizeof a); host_path(GSTR(ARG(c, 1)), b, sizeof b);
    FILE *in = fopen(a, "rb"), *out = in ? fopen(b, "wb") : NULL; int ok = in && out;
    char buf[65536]; size_t n;
    while (ok && (n = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, n, out);
    if (in) fclose(in); if (out) fclose(out);
    RET(c, ok, 3);
}
SHIM(CreateDirectoryA) { char p[1024]; host_path(GSTR(ARG(c, 0)), p, sizeof p); int r = mkdir(p, 0755); RET(c, r == 0, 2); }
SHIM(GetFileAttributesA) {
    char p[1024]; host_path(GSTR(ARG(c, 0)), p, sizeof p); struct stat st;
    if (stat(p, &st)) { SETERR(2); RET(c, 0xFFFFFFFFu, 1); return; }
    RET(c, S_ISDIR(st.st_mode) ? 0x10 : 0x80, 1);
}
SHIM(GetCurrentDirectoryA) {
    uint32_t n = ARG(c, 0), buf = ARG(c, 1);
    const char *d = "C:\\Games\\FalloutNV"; uint32_t l = (uint32_t)strlen(d);
    if (n > l) { memcpy(MEM + buf, d, l + 1); RET(c, l, 2); } else RET(c, l + 1, 2);
}
SHIM(GetFullPathNameA) {
    const char *in = GSTR(ARG(c, 0)); uint32_t n = ARG(c, 1), buf = ARG(c, 2), fp = ARG(c, 3);
    char out[1024];
    if (in[0] && in[1] == ':') snprintf(out, sizeof out, "%s", in);
    else snprintf(out, sizeof out, "C:\\Games\\FalloutNV\\%s", in);
    uint32_t l = (uint32_t)strlen(out);
    if (n > l) { memcpy(MEM + buf, out, l + 1); if (fp) { char *s = strrchr((char *)MEM + buf, '\\'); P32(fp, s ? buf + (uint32_t)(s - (char *)(MEM + buf)) + 1 : buf); } RET(c, l, 4); }
    else RET(c, l + 1, 4);
}
SHIM(GetDriveTypeA) { RET(c, 3, 1); }   // DRIVE_FIXED
SHIM(CompareFileTime) {
    uint64_t a, b; memcpy(&a, MEM + ARG(c, 0), 8); memcpy(&b, MEM + ARG(c, 1), 8);
    RET(c, a < b ? 0xFFFFFFFFu : a > b, 2);
}

// ---- FindFirstFile / FindNextFile ------------------------------------------------------------
typedef struct { DIR *d; char dir[1024]; char pat[256]; } FindObj;
static int find_fill(FindObj *f, uint32_t out) {
    struct dirent *e;
    while ((e = readdir(f->d))) {
        if (e->d_name[0] == '.' && e->d_name[1] == '_') continue;     // exFAT AppleDouble junk
        if (fnmatch(f->pat, e->d_name, FNM_CASEFOLD)) continue;
        char full[1400]; snprintf(full, sizeof full, "%s/%s", f->dir, e->d_name);
        struct stat st; if (stat(full, &st)) continue;
        memset(MEM + out, 0, 320);
        P32(out, S_ISDIR(st.st_mode) ? 0x10 : 0x80);
        uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ull) * 10000000ull;
        memcpy(MEM + out + 4, &ft, 8); memcpy(MEM + out + 12, &ft, 8); memcpy(MEM + out + 20, &ft, 8);
        P32(out + 28, (uint32_t)((uint64_t)st.st_size >> 32)); P32(out + 32, (uint32_t)st.st_size);
        snprintf((char *)MEM + out + 44, 260, "%s", e->d_name);
        return 1;
    }
    return 0;
}
SHIM(FindFirstFileA) {
    char p[1024]; host_path(GSTR(ARG(c, 0)), p, sizeof p);
    FindObj *f = calloc(1, sizeof *f);
    char *slash = strrchr(p, '/');
    if (slash) { *slash = 0; snprintf(f->dir, sizeof f->dir, "%s", p[0] ? p : "/"); snprintf(f->pat, sizeof f->pat, "%s", slash + 1); }
    else { snprintf(f->dir, sizeof f->dir, "."); snprintf(f->pat, sizeof f->pat, "%s", p); }
    f->d = opendir(f->dir);
    if (!f->d || !find_fill(f, ARG(c, 1))) { if (f->d) closedir(f->d); free(f); SETERR(2); RET(c, 0xFFFFFFFFu, 2); return; }
    RET(c, handle_new(H_FIND, f), 2);
}
SHIM(FindNextFileA) {
    FindObj *f = handle_get(ARG(c, 0), H_FIND);
    int ok = f && find_fill(f, ARG(c, 1));
    if (!ok) SETERR(18);    // ERROR_NO_MORE_FILES
    RET(c, ok, 2);
}
SHIM(FindClose) { FindObj *f = handle_get(ARG(c, 0), H_FIND); if (f) { closedir(f->d); free(f); handle_close(ARG(c, 0)); } RET(c, 1, 1); }

// ---- INI profile functions (Fallout.ini & friends) -------------------------------------------
static int ini_get(const char *file, const char *sec, const char *key, char *out, size_t n) {
    char p[1024]; host_path(file, p, sizeof p);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    char line[2048], cur[256] = ""; int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        if (*s == '[') { char *e = strchr(s, ']'); if (e) { *e = 0; snprintf(cur, sizeof cur, "%s", s + 1); } continue; }
        if (strcasecmp(cur, sec)) continue;
        char *eq = strchr(s, '='); if (!eq) continue;
        *eq = 0; char *k = s, *v = eq + 1;
        for (char *t = eq - 1; t >= k && (*t == ' ' || *t == '\t'); t--) *t = 0;
        if (strcasecmp(k, key)) continue;
        v[strcspn(v, "\r\n")] = 0;
        while (*v == ' ' || *v == '\t') v++;
        size_t vl = strlen(v);
        while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) v[--vl] = 0;
        // Windows strips one pair of matching surrounding quotes from profile values
        if (vl >= 2 && (v[0] == '"' || v[0] == '\'') && v[vl - 1] == v[0]) { v[vl - 1] = 0; v++; }
        snprintf(out, n, "%s", v); found = 1; break;
    }
    fclose(f);
    return found;
}
SHIM(GetPrivateProfileStringA) {
    const char *sec = GSTR(ARG(c, 0)), *key = GSTR(ARG(c, 1)), *def = GSTR(ARG(c, 2));
    uint32_t buf = ARG(c, 3), n = ARG(c, 4); const char *file = GSTR(ARG(c, 5));
    char v[2048];
    if (!sec || !key || !ini_get(file, sec, key, v, sizeof v)) snprintf(v, sizeof v, "%s", def ? def : "");
    uint32_t l = (uint32_t)strlen(v); if (l >= n) l = n - 1;
    memcpy(MEM + buf, v, l); MEM[buf + l] = 0;
    RET(c, l, 6);
}
SHIM(GetPrivateProfileIntA) {
    char v[256];
    uint32_t r = ini_get(GSTR(ARG(c, 3)), GSTR(ARG(c, 0)), GSTR(ARG(c, 1)), v, sizeof v) ? (uint32_t)strtol(v, NULL, 0) : ARG(c, 2);
    RET(c, r, 4);
}
// INI write: replace key in its section, or append to the section, or append a new section.
// A NULL key deletes the section, a NULL value deletes the key (Windows semantics).
SHIM(WritePrivateProfileStringA) {
    const char *sec = GSTR(ARG(c, 0)), *key = GSTR(ARG(c, 1)), *val = GSTR(ARG(c, 2)), *file = GSTR(ARG(c, 3));
    char p[1024]; host_path(file, p, sizeof p);
    FILE *f = fopen(p, "r");
    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); out[0] = 0;
#define APPEND(str) do { size_t l_ = strlen(str); while (len + l_ + 1 > cap) { cap *= 2; out = realloc(out, cap); } memcpy(out + len, str, l_ + 1); len += l_; } while (0)
    char line[2048], cur[256] = ""; int in_sec = 0, done = 0, seen_sec = 0;
    while (f && fgets(line, sizeof line, f)) {
        char *t = line; while (*t == ' ' || *t == '\t') t++;
        if (*t == '[') {
            if (in_sec && !done && key && val) { char kv[2300]; snprintf(kv, sizeof kv, "%s=%s\n", key, val); APPEND(kv); done = 1; }
            char *e = strchr(t, ']'); if (e) { size_t n = (size_t)(e - t - 1); if (n >= sizeof cur) n = sizeof cur - 1; memcpy(cur, t + 1, n); cur[n] = 0; }
            in_sec = !strcasecmp(cur, sec); if (in_sec) seen_sec = 1;
            if (in_sec && !key) continue;                       // deleting the section header
            APPEND(line); continue;
        }
        if (in_sec) {
            if (!key) continue;                                 // deleting the whole section
            char *eq = strchr(t, '=');
            if (eq) {
                char k[256]; size_t n = (size_t)(eq - t); while (n && (t[n - 1] == ' ' || t[n - 1] == '\t')) n--;
                if (n >= sizeof k) n = sizeof k - 1;
                memcpy(k, t, n); k[n] = 0;
                if (!strcasecmp(k, key)) {
                    if (val && !done) { char kv[2300]; snprintf(kv, sizeof kv, "%s=%s\n", key, val); APPEND(kv); }
                    done = 1; continue;
                }
            }
        }
        APPEND(line);
    }
    if (f) fclose(f);
    if (key && val && !done) {
        char kv[2600];
        if (in_sec) snprintf(kv, sizeof kv, "%s=%s\n", key, val);
        else snprintf(kv, sizeof kv, "%s[%s]\n%s=%s\n", len && out[len - 1] != '\n' ? "\n" : "", sec, key, val);
        if (seen_sec && !in_sec) {
            // section exists but was not the last one: rewrite by inserting after its header
            char hdr[300]; snprintf(hdr, sizeof hdr, "[%s]", sec);
            char *h = strcasestr(out, hdr);
            if (h) { char *nl = strchr(h, '\n'); size_t at = nl ? (size_t)(nl - out) + 1 : len; char ins[2300]; snprintf(ins, sizeof ins, "%s=%s\n", key, val);
                     size_t il = strlen(ins); while (len + il + 1 > cap) { cap *= 2; out = realloc(out, cap); }
                     memmove(out + at + il, out + at, len - at + 1); memcpy(out + at, ins, il); len += il; }
        } else APPEND(kv);
    }
#undef APPEND
    FILE *w = fopen(p, "w");
    if (w) { fwrite(out, 1, len, w); fclose(w); }
    free(out);
    RET(c, w != NULL, 4);
}

SHIM_TABLE(file_shims,
    E(CreateFileA) E(CreateFileW) E(ReadFile) E(WriteFile) E(GetFileSize) E(GetFileSizeEx) E(SetFilePointer)
    E(SetFilePointerEx) E(SetEndOfFile) E(FlushFileBuffers) E(DeleteFileA) E(MoveFileA) E(CopyFileA)
    E(CreateDirectoryA) E(GetFileAttributesA) E(GetCurrentDirectoryA) E(GetFullPathNameA) E(GetDriveTypeA)
    E(CompareFileTime) E(FindFirstFileA) E(FindNextFileA) E(FindClose) E(GetPrivateProfileStringA)
    E(GetPrivateProfileIntA) E(WritePrivateProfileStringA))
