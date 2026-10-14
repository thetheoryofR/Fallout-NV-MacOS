#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "input.h"

static pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
static uint8_t keys[256];
static int32_t mdx, mdy, mdz;
static uint8_t mbtn[8];
#define QN 1024
typedef struct { uint32_t ofs, data; } Ev;
static Ev q[2][QN];
static int qh[2], qt[2];

static void push(int dev, uint32_t ofs, uint32_t data) {
    int n = (qt[dev] + 1) % QN;
    if (n == qh[dev]) qh[dev] = (qh[dev] + 1) % QN;       // drop oldest on overflow
    q[dev][qt[dev]] = (Ev){ofs, data};
    qt[dev] = n;
}

// DIK scancode -> Windows virtual key + unshifted character (0 = none), for WM_KEYDOWN / WM_CHAR
static const struct { uint8_t vk; char ch; } dikmap[256] = {
    [0x01] = {0x1B, 27}, [0x0E] = {0x08, 8}, [0x0F] = {0x09, 9}, [0x1C] = {0x0D, 13}, [0x39] = {0x20, ' '},
    [0x29] = {0xC0, '`'}, [0x0C] = {0xBD, '-'}, [0x0D] = {0xBB, '='}, [0x1A] = {0xDB, '['}, [0x1B] = {0xDD, ']'},
    [0x27] = {0xBA, ';'}, [0x28] = {0xDE, '\''}, [0x2B] = {0xDC, '\\'}, [0x33] = {0xBC, ','}, [0x34] = {0xBE, '.'}, [0x35] = {0xBF, '/'},
    [0x02] = {'1', '1'}, [0x03] = {'2', '2'}, [0x04] = {'3', '3'}, [0x05] = {'4', '4'}, [0x06] = {'5', '5'},
    [0x07] = {'6', '6'}, [0x08] = {'7', '7'}, [0x09] = {'8', '8'}, [0x0A] = {'9', '9'}, [0x0B] = {'0', '0'},
    [0x10] = {'Q', 'q'}, [0x11] = {'W', 'w'}, [0x12] = {'E', 'e'}, [0x13] = {'R', 'r'}, [0x14] = {'T', 't'}, [0x15] = {'Y', 'y'},
    [0x16] = {'U', 'u'}, [0x17] = {'I', 'i'}, [0x18] = {'O', 'o'}, [0x19] = {'P', 'p'}, [0x1E] = {'A', 'a'}, [0x1F] = {'S', 's'},
    [0x20] = {'D', 'd'}, [0x21] = {'F', 'f'}, [0x22] = {'G', 'g'}, [0x23] = {'H', 'h'}, [0x24] = {'J', 'j'}, [0x25] = {'K', 'k'},
    [0x26] = {'L', 'l'}, [0x2C] = {'Z', 'z'}, [0x2D] = {'X', 'x'}, [0x2E] = {'C', 'c'}, [0x2F] = {'V', 'v'}, [0x30] = {'B', 'b'},
    [0x31] = {'N', 'n'}, [0x32] = {'M', 'm'}, [0x2A] = {0x10, 0}, [0x36] = {0x10, 0}, [0x1D] = {0x11, 0}, [0x38] = {0x12, 0},
    [0xC8] = {0x26, 0}, [0xD0] = {0x28, 0}, [0xCB] = {0x25, 0}, [0xCD] = {0x27, 0}, [0x3B] = {0x70, 0}, [0x3C] = {0x71, 0},
    [0x3D] = {0x72, 0}, [0x3E] = {0x73, 0}, [0x3F] = {0x74, 0}, [0x40] = {0x75, 0}, [0x41] = {0x76, 0}, [0x42] = {0x77, 0},
    [0x43] = {0x78, 0}, [0x44] = {0x79, 0}, [0x57] = {0x7A, 0}, [0x58] = {0x7B, 0}, [0xD3] = {0x2E, 0}, [0xC7] = {0x24, 0},
    [0xCF] = {0x23, 0}, [0xC9] = {0x21, 0}, [0xD1] = {0x22, 0}, [0x9C] = {0x0D, 13}, [0x3A] = {0x14, 0},
};
void host_post_message(uint32_t msg, uint32_t wp, uint32_t lp) __attribute__((weak));
void host_post_message(uint32_t msg, uint32_t wp, uint32_t lp) { (void)msg; (void)wp; (void)lp; }
void input_key(int dik, int down) {
    if (dik <= 0 || dik > 255) return;
    pthread_mutex_lock(&lk);
    int changed = (keys[dik] != 0) != (down != 0);
    if (changed) { keys[dik] = down ? 0x80 : 0; push(0, (uint32_t)dik, down ? 0x80 : 0); }
    int shift = keys[0x2A] || keys[0x36];
    pthread_mutex_unlock(&lk);
    if (!changed || !dikmap[dik].vk) return;
    uint32_t lp = 1u | ((uint32_t)(dik & 0x7F) << 16) | (dik & 0x80 ? 1u << 24 : 0) | (down ? 0 : 0xC0000000u);
    host_post_message(down ? 0x0100 : 0x0101, dikmap[dik].vk, lp);              // WM_KEYDOWN / WM_KEYUP
    char ch = dikmap[dik].ch;
    if (down && ch) {
        if (shift && ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
        host_post_message(0x0102, (uint8_t)ch, lp);                               // WM_CHAR
    }
}
void input_mouse_move(int dx, int dy) {
    pthread_mutex_lock(&lk);
    mdx += dx; mdy += dy;
    if (dx) push(1, 0, (uint32_t)dx);
    if (dy) push(1, 4, (uint32_t)dy);
    pthread_mutex_unlock(&lk);
}
void input_mouse_wheel(int dz) { pthread_mutex_lock(&lk); mdz += dz; push(1, 8, (uint32_t)dz); pthread_mutex_unlock(&lk); }
void input_mouse_button(int b, int down) {
    if (b < 0 || b > 7) return;
    pthread_mutex_lock(&lk);
    mbtn[b] = down ? 0x80 : 0; push(1, 12 + (uint32_t)b, down ? 0x80 : 0);
    pthread_mutex_unlock(&lk);
}

void input_keyboard_state(uint8_t out[256]) { pthread_mutex_lock(&lk); memcpy(out, keys, 256); pthread_mutex_unlock(&lk); }
void input_mouse_state(int32_t *dx, int32_t *dy, int32_t *dz, uint8_t b[8]) {
    pthread_mutex_lock(&lk);
    *dx = mdx; *dy = mdy; *dz = mdz; mdx = mdy = mdz = 0; memcpy(b, mbtn, 8);
    pthread_mutex_unlock(&lk);
}
int input_pending(int dev) { pthread_mutex_lock(&lk); int n = (qt[dev] - qh[dev] + QN) % QN; pthread_mutex_unlock(&lk); return n; }
int input_pop_event(int dev, uint32_t *ofs, uint32_t *data, int peek_index) {
    pthread_mutex_lock(&lk);
    int n = (qt[dev] - qh[dev] + QN) % QN, ok = 0;
    if (peek_index >= 0) { if (peek_index < n) { Ev e = q[dev][(qh[dev] + peek_index) % QN]; *ofs = e.ofs; *data = e.data; ok = 1; } }
    else if (n) { Ev e = q[dev][qh[dev]]; qh[dev] = (qh[dev] + 1) % QN; *ofs = e.ofs; *data = e.data; ok = 1; }
    pthread_mutex_unlock(&lk);
    return ok;
}

// ---- input script ------------------------------------------------------------------------------------
// One event per line, applied when the presented-frame counter reaches <frame>:
//   <frame> key <dik> down|up          e.g. 300 key 28 down   (28 = Enter)
//   <frame> tap <dik>                  press now, release 3 frames later
//   <frame> hold <dik> <frames>        press now, release after <frames>
//   <frame> mouse <dx> <dy>            relative motion
//   <frame> button <n> down|up
//   <frame> click <n>
//   <frame> quit
//   <frame> dump                     save this frame's backbuffer (frame_<n>.png)
//   <frame> waitdraws <n> [<stable>]  from <frame> on, pause the script until a frame has exactly n
//                                     draws for <stable> consecutive frames (default 30); later
//                                     frame numbers are then counted from that moment
typedef struct { uint64_t frame; char cmd[16]; int a, b; } Step;
static Step *steps; static int nsteps, cursor;
static int64_t shift;
static volatile int dump_req;
int input_take_dump_request(void) { int r = dump_req; dump_req = 0; return r; }               // added to step frames once a waitdraws has been satisfied
static uint64_t last_draws, stable_run;
void input_frame_draws(uint64_t draws_this_frame) { last_draws = draws_this_frame; }
static void load_script(void) {
    static int loaded;
    if (loaded) return;
    loaded = 1;
    const char *p = getenv("FNV_INPUT_SCRIPT");
    if (!p) return;
    FILE *f = fopen(p, "r");
    if (!f) { fprintf(stderr, "[input] cannot open %s\n", p); return; }
    char line[256];
    int cap = 256; steps = malloc(sizeof(Step) * (size_t)cap);
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        Step s = {0}; char a[32] = "", b[32] = "";
        if (sscanf(line, "%llu %15s %31s %31s", (unsigned long long *)&s.frame, s.cmd, a, b) < 2) continue;
        s.a = atoi(a); s.b = !strcmp(b, "down") ? 1 : !strcmp(b, "up") ? 0 : atoi(b);
        if (!strcmp(s.cmd, "tap") || !strcmp(s.cmd, "click") || !strcmp(s.cmd, "hold")) {
            int len = !strcmp(s.cmd, "hold") ? s.b : 3;
            Step dn = s, up = s;
            strcpy(dn.cmd, s.cmd[0] == 'c' ? "button" : "key"); dn.b = 1;
            strcpy(up.cmd, dn.cmd); up.b = 0; up.frame = s.frame + (uint64_t)len;
            if (nsteps + 2 >= cap) { cap *= 2; steps = realloc(steps, sizeof(Step) * (size_t)cap); }
            steps[nsteps++] = dn; steps[nsteps++] = up;
            continue;
        }
        if (nsteps + 1 >= cap) { cap *= 2; steps = realloc(steps, sizeof(Step) * (size_t)cap); }
        steps[nsteps++] = s;
    }
    fclose(f);
    // stable sort by frame
    for (int i = 1; i < nsteps; i++) { Step t = steps[i]; int j = i - 1; while (j >= 0 && steps[j].frame > t.frame) { steps[j + 1] = steps[j]; j--; } steps[j + 1] = t; }
    fprintf(stderr, "[input] script %s: %d events\n", p, nsteps);
}
void input_script_tick(uint64_t frame) {
    load_script();
    // FNV_QUIT_AFTER=<seconds>: clean exit (atexit handlers run, so a recording is finalized)
    static double quit_after = -1; static struct timespec t0;
    if (quit_after < 0) { const char *q = getenv("FNV_QUIT_AFTER"); quit_after = q ? atof(q) : 0; clock_gettime(CLOCK_MONOTONIC, &t0); }
    {   // heap accounting every 30 s of wall time
        extern void gheap_report(void) __attribute__((weak));
        static struct timespec last;
        struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
        if (t.tv_sec - last.tv_sec >= 30) { last = t; if (gheap_report) gheap_report(); }
    }
    if (quit_after > 0) {
        struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
        double el = (double)(t.tv_sec - t0.tv_sec) + (double)(t.tv_nsec - t0.tv_nsec) * 1e-9;
        if (el >= quit_after) { fprintf(stderr, "[input] FNV_QUIT_AFTER: %.0f s elapsed at frame %llu, exiting\n", el, (unsigned long long)frame); exit(0); }
    }
    while (cursor < nsteps && (int64_t)steps[cursor].frame + shift <= (int64_t)frame) {
        Step *s = &steps[cursor];
        if (!strcmp(s->cmd, "waitdraws")) {
            uint64_t need = s->b ? (uint64_t)s->b : 30;
            stable_run = last_draws == (uint64_t)s->a ? stable_run + 1 : 0;
            if (stable_run < need) return;
            fprintf(stderr, "[input] waitdraws %d satisfied at frame %llu\n", s->a, (unsigned long long)frame);
            shift = (int64_t)frame - (int64_t)s->frame;
            stable_run = 0; cursor++;
            continue;
        }
        cursor++;
        if (!strcmp(s->cmd, "key")) input_key(s->a, s->b);
        else if (!strcmp(s->cmd, "mouse")) input_mouse_move(s->a, s->b);
        else if (!strcmp(s->cmd, "button")) input_mouse_button(s->a, s->b);
        else if (!strcmp(s->cmd, "dump")) dump_req = 1;
        else if (!strcmp(s->cmd, "quit")) { fprintf(stderr, "[input] script quit at frame %llu\n", (unsigned long long)frame); exit(0); }
    }
}
