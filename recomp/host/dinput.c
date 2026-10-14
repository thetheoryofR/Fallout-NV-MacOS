// DirectInput8 — headless for M2: a keyboard and a mouse that exist and report nothing pressed.
// M4 replaces GetDeviceState/GetDeviceData with real macOS input.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "com.h"
#include "input.h"

static uint32_t vt_di8, vt_dev;

static void QueryInterface_(CPU *c) { P32(ARG(c, 2), 0); RET(c, 0x80004002u, 3); }   // E_NOINTERFACE

// ---- IDirectInputDevice8A ---------------------------------------------------------------------
static void Dev_GetCapabilities(CPU *c) { uint32_t p = ARG(c, 1); uint32_t sz = G32(p); memset(MEM + p + 4, 0, sz > 4 ? sz - 4 : 0); RET(c, 0, 2); }
// device kind lives in the COM data word: 0 keyboard, 1 mouse
static int dev_kind(CPU *c) { return (int)G32(COM_DATA(COM_THIS(c))); }
static uint64_t n_state[2], n_data[2], n_delivered[2];
static int trace_in(void) { static int t = -1; if (t < 0) t = getenv("FNV_TRACE_INPUT") != NULL; return t; }
static void report(void) {
    static uint64_t last; uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (trace_in() && now - last > 2000000000ull) { last = now;
        fprintf(stderr, "[dinput] kbd state %llu data %llu delivered %llu | mouse state %llu data %llu delivered %llu\n",
            (unsigned long long)n_state[0], (unsigned long long)n_data[0], (unsigned long long)n_delivered[0],
            (unsigned long long)n_state[1], (unsigned long long)n_data[1], (unsigned long long)n_delivered[1]); }
}
static void Dev_GetDeviceState(CPU *c) {
    uint32_t n = ARG(c, 1), out = ARG(c, 2);
    n_state[dev_kind(c) & 1]++; report();
    memset(MEM + out, 0, n);
    if (dev_kind(c) == 0) { uint8_t k[256]; input_keyboard_state(k); memcpy(MEM + out, k, n < 256 ? n : 256); }
    else {
        int32_t dx, dy, dz; uint8_t b[8]; input_mouse_state(&dx, &dy, &dz, b);
        if (n >= 12) { P32(out, (uint32_t)dx); P32(out + 4, (uint32_t)dy); P32(out + 8, (uint32_t)dz); }
        memcpy(MEM + out + 12, b, n >= 20 ? 8 : n > 12 ? n - 12 : 0);    // DIMOUSESTATE (4 buttons) / DIMOUSESTATE2 (8)
    }
    RET(c, 0, 3);
}
// GetDeviceData(cbObjectData, rgdod, pdwInOut, dwFlags): DIDEVICEOBJECTDATA = ofs, data, time, seq, appdata
static void Dev_GetDeviceData(CPU *c) {
    uint32_t sz = ARG(c, 1), arr = ARG(c, 2), inout = ARG(c, 3), flags = ARG(c, 4), cap = G32(inout), n = 0;
    int dev = dev_kind(c), peek = (flags & 1) != 0;
    static uint32_t seq;
    n_data[dev & 1]++; report();
    if (!arr) { P32(inout, (uint32_t)input_pending(dev)); if (!peek) { uint32_t o, d; while (input_pop_event(dev, &o, &d, -1)) {} } RET(c, 0, 5); return; }
    for (; n < cap; n++) {
        uint32_t o, d;
        if (!input_pop_event(dev, &o, &d, peek ? (int)n : -1)) break;
        uint32_t e = arr + n * sz;
        memset(MEM + e, 0, sz);
        P32(e, o); P32(e + 4, d); P32(e + 8, (uint32_t)(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000)); P32(e + 12, ++seq);
    }
    P32(inout, n);
    n_delivered[dev & 1] += n;
    if (n && trace_in()) fprintf(stderr, "[dinput] dev %d delivered %u event(s), first ofs %#x data %#x\n", dev, n, G32(arr), G32(arr + 4));
    RET(c, 0, 5);
}
COM_STUB_OK(Dev_SetDataFormat, 1)
COM_STUB_OK(Dev_SetCooperativeLevel, 2)
COM_STUB_OK(Dev_SetProperty, 2)
COM_STUB_OK(Dev_GetProperty, 2)
COM_STUB_OK(Dev_Acquire, 0)
COM_STUB_OK(Dev_Unacquire, 0)
COM_STUB_OK(Dev_SetEventNotification, 1)
COM_STUB_OK(Dev_Poll, 0)
COM_STUB_OK(Dev_EnumObjects, 3)
COM_STUB_OK(Dev_GetObjectInfo, 3)
COM_STUB_OK(Dev_GetDeviceInfo, 1)
COM_STUB_OK(Dev_RunControlPanel, 2)
COM_STUB_OK(Dev_Initialize, 3)

static const ComMethod dev_methods[] = {
    {"QueryInterface", QueryInterface_, 2}, {"AddRef", com_AddRef, 0}, {"Release", com_Release, 0},
    {"GetCapabilities", Dev_GetCapabilities, 1}, {"EnumObjects", Dev_EnumObjects, 3}, {"GetProperty", Dev_GetProperty, 2},
    {"SetProperty", Dev_SetProperty, 2}, {"Acquire", Dev_Acquire, 0}, {"Unacquire", Dev_Unacquire, 0},
    {"GetDeviceState", Dev_GetDeviceState, 2}, {"GetDeviceData", Dev_GetDeviceData, 4},
    {"SetDataFormat", Dev_SetDataFormat, 1}, {"SetEventNotification", Dev_SetEventNotification, 1},
    {"SetCooperativeLevel", Dev_SetCooperativeLevel, 2}, {"GetObjectInfo", Dev_GetObjectInfo, 3},
    {"GetDeviceInfo", Dev_GetDeviceInfo, 1}, {"RunControlPanel", Dev_RunControlPanel, 2},
    {"Initialize", Dev_Initialize, 3}, {"CreateEffect", NULL, 4}, {"EnumEffects", NULL, 3},
    {"GetEffectInfo", NULL, 2}, {"GetForceFeedbackState", NULL, 1}, {"SendForceFeedbackCommand", NULL, 1},
    {"EnumCreatedEffectObjects", NULL, 3}, {"Escape", NULL, 1}, {"Poll", Dev_Poll, 0},
    {"SendDeviceData", NULL, 4}, {"EnumEffectsInFile", NULL, 4}, {"WriteEffectToFile", NULL, 4},
    {"BuildActionMap", NULL, 3}, {"SetActionMap", NULL, 3}, {"GetImageInfo", NULL, 1},
};

// ---- IDirectInput8A ---------------------------------------------------------------------------
static void DI_CreateDevice(CPU *c) {
    if (!vt_dev) vt_dev = com_vtable("IDirectInputDevice8A", dev_methods, (int)(sizeof dev_methods / sizeof *dev_methods));
    uint32_t guid = ARG(c, 1);
    fprintf(stderr, "[dinput] CreateDevice guid %08x-...\n", G32(guid));
    uint32_t d = com_new(vt_dev, 16);
    P32(COM_DATA(d), G32(guid) == 0x6f1d2b60u ? 1u : 0u);      // GUID_SysMouse / GUID_SysKeyboard
    P32(ARG(c, 2), d);
    RET(c, 0, 4);
}
static void DI_EnumDevices(CPU *c) { RET(c, 0, 5); }      // nothing to enumerate (no gamepads yet)
COM_STUB_OK(DI_GetDeviceStatus, 1)
COM_STUB_OK(DI_RunControlPanel, 2)
COM_STUB_OK(DI_Initialize, 2)

static const ComMethod di8_methods[] = {
    {"QueryInterface", QueryInterface_, 2}, {"AddRef", com_AddRef, 0}, {"Release", com_Release, 0},
    {"CreateDevice", DI_CreateDevice, 3}, {"EnumDevices", DI_EnumDevices, 4}, {"GetDeviceStatus", DI_GetDeviceStatus, 1},
    {"RunControlPanel", DI_RunControlPanel, 2}, {"Initialize", DI_Initialize, 2}, {"FindDevice", NULL, 3},
    {"EnumDevicesBySemantics", NULL, 5}, {"ConfigureDevices", NULL, 4},
};

static void DirectInput8Create_(CPU *c) {
    if (!vt_di8) vt_di8 = com_vtable("IDirectInput8A", di8_methods, (int)(sizeof di8_methods / sizeof *di8_methods));
    P32(ARG(c, 3), com_new(vt_di8, 0));
    RET(c, 0, 5);
}

const ShimTable dinput_shims = { (const Shim[]){ {"DirectInput8Create", DirectInput8Create_} }, 1 };

// ---- XInput 1.3: no controller connected yet (M4: GameController framework) ---------------------
static void XInputGetState_(CPU *c) { RET(c, 1167 /* ERROR_DEVICE_NOT_CONNECTED */, 2); }
static void XInputSetState_(CPU *c) { RET(c, 1167, 2); }
static void XInputGetCapabilities_(CPU *c) { RET(c, 1167, 3); }
const ShimTable xinput_shims = { (const Shim[]){ {"xinput1_3#2", XInputGetState_}, {"xinput1_3#3", XInputSetState_},
    {"XInputGetState", XInputGetState_}, {"XInputSetState", XInputSetState_}, {"XInputGetCapabilities", XInputGetCapabilities_} }, 5 };
