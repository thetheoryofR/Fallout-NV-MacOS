// Headless (M2) user32 / gdi32 / advapi32 / shell32 / ole32 / winmm / steam_api shims.
// The window exists only as a handle and an empty message queue until the Metal layer (M3).
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include "shims.h"
#include <time.h>

#define FAKE_HWND 0x00010010u
static uint32_t wndproc;

// ---- a small Win32 message queue; DispatchMessage / SendMessage run the game's own WndProc ----------
#include <pthread.h>
typedef struct { uint32_t msg, wp, lp; } QMsg;
static QMsg mq[512]; static int mq_h, mq_t;
static pthread_mutex_t mq_lk = PTHREAD_MUTEX_INITIALIZER;
void host_post_message(uint32_t msg, uint32_t wp, uint32_t lp) {
    pthread_mutex_lock(&mq_lk);
    int n = (mq_t + 1) % 512;
    if (n != mq_h) { mq[mq_t] = (QMsg){msg, wp, lp}; mq_t = n; }
    pthread_mutex_unlock(&mq_lk);
}
static uint32_t call_wndproc(CPU *c, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    if (!wndproc) return 0;
    uint32_t esp = REG(c, R_ESP), saved_eax = REG(c, R_EAX);
    uint32_t sp = esp - 64;                       // below the shim's own frame
    P32(sp, HOST_EXIT_THUNK); P32(sp + 4, hwnd); P32(sp + 8, msg); P32(sp + 12, wp); P32(sp + 16, lp);
    SETREG(c, R_ESP, sp);
    rt_call(c, wndproc);                          // stdcall: callee pops the 4 args + return address
    uint32_t r = REG(c, R_EAX);
    SETREG(c, R_ESP, esp); (void)saved_eax;
    return r;
}

// ---- user32 ------------------------------------------------------------------------------------
SHIM(RegisterClassA) { wndproc = G32(ARG(c, 0) + 4); fprintf(stderr, "[host] RegisterClassA wndproc %#x\n", wndproc); RET(c, 0xC001, 1); }
SHIM(CreateWindowExA) {
    // the window starts active: tell the game the way Windows would
    host_post_message(0x001C /* WM_ACTIVATEAPP */, 1, 0);
    host_post_message(0x0006 /* WM_ACTIVATE */, 1 /* WA_ACTIVE */, 0);
    host_post_message(0x0007 /* WM_SETFOCUS */, 0, 0);
    fprintf(stderr, "[host] CreateWindowExA(\"%s\", %ux%u) -> headless window\n", GSTR(ARG(c, 2)) ? GSTR(ARG(c, 2)) : "", ARG(c, 6), ARG(c, 7));
    RET(c, FAKE_HWND, 12);
}
SHIM(DestroyWindow) { RET(c, 1, 1); }
SHIM(ShowWindow) { RET(c, 1, 2); }
SHIM(UpdateWindow) { RET(c, 1, 1); }
SHIM(SetWindowPos) { RET(c, 1, 7); }
SHIM(SetWindowTextA) { RET(c, 1, 2); }
SHIM(GetWindowTextA) { if (ARG(c, 2)) MEM[ARG(c, 1)] = 0; RET(c, 0, 3); }
SHIM(GetClassNameA) { if (ARG(c, 2)) MEM[ARG(c, 1)] = 0; RET(c, 0, 3); }
SHIM(GetWindow) { RET(c, 0, 2); }
SHIM(GetWindowLongA) { RET(c, 0, 2); }
SHIM(GetClassLongA) { RET(c, 0, 2); }
SHIM(EnumChildWindows) { RET(c, 1, 3); }
SHIM(FindWindowA) { RET(c, 0, 2); }
SHIM(GetActiveWindow) { RET(c, FAKE_HWND, 0); }
SHIM(GetForegroundWindow) { RET(c, FAKE_HWND, 0); }
SHIM(GetFocus) { RET(c, FAKE_HWND, 0); }
SHIM(SetForegroundWindow) { RET(c, 1, 1); }
SHIM(GetClientRect) { uint32_t r = ARG(c, 1); P32(r, 0); P32(r + 4, 0); P32(r + 8, 1280); P32(r + 12, 720); RET(c, 1, 2); }
SHIM(AdjustWindowRect) { RET(c, 1, 3); }
SHIM(AdjustWindowRectEx) { RET(c, 1, 4); }
SHIM(GetSystemMetrics) { uint32_t i = ARG(c, 0); RET(c, i == 0 ? 1920 : i == 1 ? 1080 : 0, 1); }
SHIM(EnumDisplayDevicesA) { RET(c, 0, 4); }
SHIM(LoadIconA) { RET(c, 0x00020001, 2); }
SHIM(LoadCursorA) { RET(c, 0x00020002, 2); }
SHIM(ShowCursor) { RET(c, 0, 1); }
SHIM(GetDoubleClickTime) { RET(c, 500, 0); }
SHIM(SwapMouseButton) { RET(c, 0, 1); }
SHIM(GetAsyncKeyState) { RET(c, 0, 1); }
SHIM(SendInput) { RET(c, ARG(c, 0), 3); }
SHIM(SetWindowsHookExA) { RET(c, 0x00030001, 4); }
SHIM(UnhookWindowsHookEx) { RET(c, 1, 1); }
SHIM(CallNextHookEx) { RET(c, 0, 4); }
void host_pump_events(void);
SHIM(PeekMessageA) {
    host_pump_events();
    uint32_t m = ARG(c, 0), remove = ARG(c, 4) & 1;
    pthread_mutex_lock(&mq_lk);
    if (mq_h == mq_t) { pthread_mutex_unlock(&mq_lk); RET(c, 0, 5); return; }
    QMsg q = mq[mq_h];
    if (remove) mq_h = (mq_h + 1) % 512;
    pthread_mutex_unlock(&mq_lk);
    P32(m, FAKE_HWND); P32(m + 4, q.msg); P32(m + 8, q.wp); P32(m + 12, q.lp);
    P32(m + 16, (uint32_t)(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000)); P32(m + 20, 0); P32(m + 24, 0);
    RET(c, 1, 5);
}
SHIM(TranslateMessage) { RET(c, 0, 1); }
SHIM(DispatchMessageA) {
    uint32_t m = ARG(c, 0);
    uint32_t r = call_wndproc(c, G32(m), G32(m + 4), G32(m + 8), G32(m + 12));
    RET(c, r, 1);
}
SHIM(SendMessageA) { uint32_t r = call_wndproc(c, ARG(c, 0), ARG(c, 1), ARG(c, 2), ARG(c, 3)); RET(c, r, 4); }
SHIM(DefWindowProcA) { RET(c, 0, 4); }
SHIM(MessageBoxA) {
    fprintf(stderr, "[host] MessageBoxA: \"%s\" — %s\n", GSTR(ARG(c, 2)) ? GSTR(ARG(c, 2)) : "", GSTR(ARG(c, 1)) ? GSTR(ARG(c, 1)) : "");
    RET(c, 1, 4);    // IDOK
}
// ---- gdi32 / comctl32 ----------------------------------------------------------------------------
SHIM(GetStockObject) { RET(c, 0x00040001, 1); }
SHIM(InitCommonControlsEx) { RET(c, 1, 1); }
SHIM(ImageList_LoadImageA) { RET(c, 0x00050001, 7); }
SHIM(ImageList_Destroy) { RET(c, 1, 1); }

// ---- advapi32: an empty registry (the game falls back to defaults / its INIs) -------------------
SHIM(RegOpenKeyExA) { RET(c, 2, 5); }                // ERROR_FILE_NOT_FOUND
SHIM(RegCreateKeyExA) { if (ARG(c, 7)) P32(ARG(c, 7), 0x00060001); RET(c, 0, 9); }
SHIM(RegQueryValueExA) { RET(c, 2, 6); }
SHIM(RegSetValueExA) { RET(c, 0, 6); }
SHIM(RegCloseKey) { RET(c, 0, 1); }
SHIM(GetUserNameA) { const char *u = "Player"; strcpy((char *)MEM + ARG(c, 0), u); P32(ARG(c, 1), 7); RET(c, 1, 2); }

// ---- shell32: special folders live under the run directory --------------------------------------
SHIM(SHGetFolderPathA) {
    const char *p = "C:\\Games\\FalloutNV\\UserDocuments";
    mkdir("UserDocuments", 0755);
    strcpy((char *)MEM + ARG(c, 4), p);
    RET(c, 0, 5);
}
// Nothing external is launched (e.g. FalloutNVLauncher.exe). FNV tests the result for != 0, not the
// documented > 32, so failure has to be 0 for it to carry on with default settings.
SHIM(ShellExecuteA) {
    fprintf(stderr, "[host] ShellExecuteA(%s) -> not launched\n", GSTR(ARG(c, 2)) ? GSTR(ARG(c, 2)) : "");
    RET(c, 0, 6);
}
SHIM(CommandLineToArgvW) { if (ARG(c, 1)) P32(ARG(c, 1), 0); RET(c, gmalloc(8), 2); }

// ---- ole32 -------------------------------------------------------------------------------------
SHIM(CoInitialize) { RET(c, 0, 1); }
SHIM(CoInitializeEx) { RET(c, 0, 2); }
SHIM(CoUninitialize) { RET(c, 0, 0); }
SHIM(CoFreeUnusedLibraries) { RET(c, 0, 0); }
SHIM(CoTaskMemAlloc) { RET(c, gmalloc(ARG(c, 0)), 1); }
SHIM(CoTaskMemFree) { gfree(ARG(c, 0)); RET(c, 0, 1); }
uint32_t dshow_create_filtergraph(uint32_t iid);
SHIM(CoCreateInstance) {
    if (G32(ARG(c, 0)) == 0xe436ebb3u) {            // CLSID_FilterGraph: DirectShow music player
        P32(ARG(c, 4), dshow_create_filtergraph(ARG(c, 3)));
        RET(c, 0, 5); return;
    }
    uint32_t g = ARG(c, 0), ig = ARG(c, 3);
    fprintf(stderr, "[host] CoCreateInstance clsid {%08x-%04x-%04x-...} iid {%08x-...} -> REGDB_E_CLASSNOTREG\n",
            G32(g), G32(g + 4) & 0xFFFF, G32(g + 4) >> 16, G32(ig));
    P32(ARG(c, 4), 0); RET(c, 0x80040154u, 5);
}

// ---- winmm -------------------------------------------------------------------------------------
SHIM(timeGetTime) { RET(c, (uint32_t)(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ull), 0); }

// ---- steam_api: report "Steam not running" so the game takes its offline path -------------------
SHIM(SteamAPI_Init) { fprintf(stderr, "[host] SteamAPI_Init -> false (offline)\n"); RET(c, 0, 0); }
SHIM(SteamAPI_IsSteamRunning) { RET(c, 0, 0); }
SHIM(SteamAPI_Shutdown) { RET(c, 0, 0); }
SHIM(SteamAPI_RunCallbacks) { RET(c, 0, 0); }
SHIM(SteamAPI_RegisterCallback) { RET(c, 0, 0); }      // cdecl: caller pops
SHIM(SteamAPI_UnregisterCallback) { RET(c, 0, 0); }
SHIM(SteamUser) { RET(c, 0, 0); }
SHIM(SteamFriends) { RET(c, 0, 0); }
SHIM(SteamUserStats) { RET(c, 0, 0); }
SHIM(SteamApps) { RET(c, 0, 0); }
SHIM(SteamUtils) { RET(c, 0, 0); }

SHIM_TABLE(win_shims,
    E(RegisterClassA) E(CreateWindowExA) E(DestroyWindow) E(ShowWindow) E(UpdateWindow) E(SetWindowPos)
    E(SetWindowTextA) E(GetWindowTextA) E(GetClassNameA) E(GetWindow) E(GetWindowLongA) E(GetClassLongA)
    E(EnumChildWindows) E(FindWindowA) E(GetActiveWindow) E(GetForegroundWindow) E(GetFocus) E(SetForegroundWindow) E(GetClientRect)
    E(AdjustWindowRect) E(AdjustWindowRectEx) E(GetSystemMetrics) E(EnumDisplayDevicesA) E(LoadIconA)
    E(LoadCursorA) E(ShowCursor) E(GetDoubleClickTime) E(SwapMouseButton) E(GetAsyncKeyState) E(SendInput)
    E(SetWindowsHookExA) E(UnhookWindowsHookEx) E(CallNextHookEx) E(PeekMessageA) E(TranslateMessage)
    E(DispatchMessageA) E(SendMessageA) E(DefWindowProcA) E(MessageBoxA) E(GetStockObject)
    E(InitCommonControlsEx) E(ImageList_LoadImageA) E(ImageList_Destroy) E(RegOpenKeyExA) E(RegCreateKeyExA)
    E(RegQueryValueExA) E(RegSetValueExA) E(RegCloseKey) E(GetUserNameA) E(SHGetFolderPathA) E(ShellExecuteA)
    E(CommandLineToArgvW) E(CoInitialize) E(CoInitializeEx) E(CoUninitialize) E(CoFreeUnusedLibraries)
    E(CoTaskMemAlloc) E(CoTaskMemFree) E(CoCreateInstance) E(timeGetTime) E(SteamAPI_Init)
    E(SteamAPI_IsSteamRunning) E(SteamAPI_Shutdown) E(SteamAPI_RunCallbacks) E(SteamAPI_RegisterCallback)
    E(SteamAPI_UnregisterCallback) E(SteamUser) E(SteamFriends) E(SteamUserStats) E(SteamApps) E(SteamUtils))
