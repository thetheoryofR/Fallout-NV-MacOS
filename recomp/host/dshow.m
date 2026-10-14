// DirectShow filter graph (CLSID_FilterGraph) for FNV's music thread: RenderFile + play/seek/volume +
// EC_COMPLETE, played with AVAudioPlayer (native MP3/WAV decoding). One guest object per interface,
// all sharing one host player.
#import <AVFoundation/AVFoundation.h>
#include <stdio.h>
#include "com.h"

@interface DSGraph : NSObject {
@public
    uint32_t ifaces[8];
}
@property(nonatomic, strong) AVAudioPlayer *player;
@property(nonatomic) BOOL running, completed_reported, complete;
@property(nonatomic) long volume;
@end
@implementation DSGraph
@end

static NSMutableDictionary<NSNumber *, DSGraph *> *graphs;
static uint32_t next_gid = 1;
enum { I_GRAPH, I_CONTROL, I_EVENT, I_AUDIO, I_SEEKING, I_POSITION, I_COUNT };
static uint32_t vt[I_COUNT];

static DSGraph *G(CPU *c) { return graphs[@(G32(COM_DATA(COM_THIS(c))))]; }
static uint32_t iface(DSGraph *g, uint32_t gid, int which) {
    if (!g->ifaces[which]) {
        uint32_t o = com_new(vt[which], 4);
        P32(COM_DATA(o), gid);
        g->ifaces[which] = o;
    }
    return g->ifaces[which];
}
static int iid_is(uint32_t p, uint32_t d1) { return G32(p) == d1; }

static void DS_QI(CPU *c) {
    uint32_t gid = G32(COM_DATA(COM_THIS(c))), iid = ARG(c, 1), out = ARG(c, 2);
    DSGraph *g = graphs[@(gid)];
    int which = -1;
    if (iid_is(iid, 0x56a8689f) || iid_is(iid, 0x56a868a9) || iid_is(iid, 0x36b73882)) which = I_GRAPH;   // IFilterGraph, IGraphBuilder, IFilterGraph2
    else if (iid_is(iid, 0x56a868b1)) which = I_CONTROL;                                                   // IMediaControl
    else if (iid_is(iid, 0x56a868b6) || iid_is(iid, 0x56a868c0)) which = I_EVENT;                         // IMediaEvent(Ex)
    else if (iid_is(iid, 0x56a868b3)) which = I_AUDIO;                                                     // IBasicAudio
    else if (iid_is(iid, 0x36b73880)) which = I_SEEKING;                                                   // IMediaSeeking
    else if (iid_is(iid, 0x56a868b2)) which = I_POSITION;                                                  // IMediaPosition
    else if (iid_is(iid, 0x00000000)) which = I_GRAPH;                                                     // IUnknown
    if (which < 0 || !g) { fprintf(stderr, "[dshow] QueryInterface {%08x} -> E_NOINTERFACE\n", G32(iid)); P32(out, 0); RET(c, 0x80004002u, 3); return; }
    P32(out, iface(g, gid, which));
    RET(c, 0, 3);
}
static void DS_AddRef(CPU *c) { RET(c, 2, 1); }
static void DS_Release(CPU *c) { RET(c, 1, 1); }
#define OKN(n) static void ok##n(CPU *c) { RET(c, 0, (n) + 1); }
OKN(0) OKN(1) OKN(2) OKN(3) OKN(4) OKN(5) OKN(8)
static void notimpl1(CPU *c) { RET(c, 0x80004001u, 2); }

// IGraphBuilder::RenderFile(LPCWSTR file, LPCWSTR playlist)
static void GB_RenderFile(CPU *c) {
    DSGraph *g = G(c);
    char wpath[1024], path[1024];
    w2a(ARG(c, 1), wpath, sizeof wpath);
    host_path(wpath, path, sizeof path);
    NSError *e = nil;
    g.player = [[AVAudioPlayer alloc] initWithContentsOfURL:[NSURL fileURLWithPath:[NSString stringWithUTF8String:path]] error:&e];
    if (!g.player) { fprintf(stderr, "[dshow] RenderFile(%s): %s\n", path, e.localizedDescription.UTF8String); RET(c, 0x80040216u /* VFW_E_NOT_FOUND */, 3); return; }
    [g.player prepareToPlay];
    g.player.volume = (float)pow(10.0, g.volume / 2000.0);
    g.complete = NO; g.completed_reported = NO;
    fprintf(stderr, "[dshow] RenderFile(%s) %.1fs\n", wpath, g.player.duration);
    RET(c, 0, 3);
}
// IMediaControl
static void MC_Run(CPU *c) { DSGraph *g = G(c); [g.player play]; g.running = YES; RET(c, 0, 1); }
static void MC_Pause(CPU *c) { DSGraph *g = G(c); [g.player pause]; g.running = NO; RET(c, 0, 1); }
static void MC_Stop(CPU *c) { DSGraph *g = G(c); [g.player stop]; g.running = NO; RET(c, 0, 1); }
static void MC_GetState(CPU *c) { DSGraph *g = G(c); P32(ARG(c, 2), g.player.playing ? 2 : g.running ? 1 : 0); RET(c, 0, 3); }
// IMediaEventEx: EC_COMPLETE once the track has played out
static void ME_GetEvent(CPU *c) {
    DSGraph *g = G(c);
    if (g.running && g.player && !g.player.playing && !g.completed_reported) {
        g.completed_reported = YES; g.complete = YES; g.running = NO;
        P32(ARG(c, 1), 1 /* EC_COMPLETE */); P32(ARG(c, 2), 0); P32(ARG(c, 3), 0);
        RET(c, 0, 5); return;
    }
    RET(c, 0x80004004u /* E_ABORT: no event */, 5);
}
static void ME_GetEventHandle(CPU *c) { P32(ARG(c, 1), 0); RET(c, 0, 2); }
static void ME_WaitForCompletion(CPU *c) { DSGraph *g = G(c); P32(ARG(c, 2), g.complete ? 1 : 0); RET(c, g.complete ? 0 : 0x80040213u /* VFW_E_TIMEOUT */, 3); }
// IBasicAudio: volume in 1/100 dB, -10000..0
static void BA_put_Volume(CPU *c) { DSGraph *g = G(c); g.volume = (long)(int32_t)ARG(c, 1); g.player.volume = (float)pow(10.0, g.volume / 2000.0); RET(c, 0, 2); }
static void BA_get_Volume(CPU *c) { P32(ARG(c, 1), (uint32_t)G(c).volume); RET(c, 0, 2); }
static void BA_get_Balance(CPU *c) { P32(ARG(c, 1), 0); RET(c, 0, 2); }
// IMediaSeeking (100 ns units)
static void put64(uint32_t p, int64_t v) { memcpy(MEM + p, &v, 8); }
static void MS_GetDuration(CPU *c) { put64(ARG(c, 1), (int64_t)(G(c).player.duration * 1e7)); RET(c, 0, 2); }
static void MS_GetCurrentPosition(CPU *c) { put64(ARG(c, 1), (int64_t)(G(c).player.currentTime * 1e7)); RET(c, 0, 2); }
static void MS_GetStopPosition(CPU *c) { put64(ARG(c, 1), (int64_t)(G(c).player.duration * 1e7)); RET(c, 0, 2); }
static void MS_SetPositions(CPU *c) {
    DSGraph *g = G(c);
    if (ARG(c, 1) && (ARG(c, 2) & 3)) { int64_t t; memcpy(&t, MEM + ARG(c, 1), 8); g.player.currentTime = (double)t / 1e7; g.complete = NO; g.completed_reported = NO; }
    RET(c, 0, 5);
}
static void MS_GetPositions(CPU *c) { if (ARG(c, 1)) put64(ARG(c, 1), (int64_t)(G(c).player.currentTime * 1e7)); if (ARG(c, 2)) put64(ARG(c, 2), (int64_t)(G(c).player.duration * 1e7)); RET(c, 0, 3); }
static void MS_GetCaps(CPU *c) { P32(ARG(c, 1), 0x1F); RET(c, 0, 2); }
static void MS_GetTimeFormat(CPU *c) { static const uint8_t TIME_FORMAT_MEDIA_TIME[16] = {0x70, 0xa6, 0x95, 0x7b, 0xc5, 0x84, 0xd0, 0x11, 0xa1, 0x18, 0x00, 0xa0, 0xc9, 0x05, 0x5e, 0x9e}; memcpy(MEM + ARG(c, 1), TIME_FORMAT_MEDIA_TIME, 16); RET(c, 0, 2); }
static void MS_GetRate(CPU *c) { double r = 1.0; memcpy(MEM + ARG(c, 1), &r, 8); RET(c, 0, 2); }
// IMediaPosition (seconds as double)
static void MP_get_Duration(CPU *c) { double d = G(c).player.duration; memcpy(MEM + ARG(c, 1), &d, 8); RET(c, 0, 2); }
static void MP_get_CurrentPosition(CPU *c) { double d = G(c).player.currentTime; memcpy(MEM + ARG(c, 1), &d, 8); RET(c, 0, 2); }
static void MP_put_CurrentPosition(CPU *c) { double d; uint32_t lo = ARG(c, 1), hi = ARG(c, 2); uint64_t b = ((uint64_t)hi << 32) | lo; memcpy(&d, &b, 8); G(c).player.currentTime = d; RET(c, 0, 3); }

#define M(n, f, a) {n, f, a}
#define UNK M("QueryInterface", DS_QI, 2), M("AddRef", DS_AddRef, 0), M("Release", DS_Release, 0)
#define DISP M("GetTypeInfoCount", ok1, 1), M("GetTypeInfo", ok3, 3), M("GetIDsOfNames", ok5, 5), M("Invoke", ok8, 8)
static const ComMethod graph_m[] = {UNK, M("AddFilter", ok2, 2), M("RemoveFilter", ok1, 1), M("EnumFilters", notimpl1, 1),
    M("FindFilterByName", ok2, 2), M("ConnectDirect", ok3, 3), M("Reconnect", ok1, 1), M("Disconnect", ok1, 1),
    M("SetDefaultSyncSource", ok0, 0), M("Connect", ok2, 2), M("Render", ok1, 1), M("RenderFile", GB_RenderFile, 2),
    M("AddSourceFilter", ok3, 3), M("SetLogFile", ok1, 1), M("Abort", ok0, 0), M("ShouldOperationContinue", ok0, 0)};
static const ComMethod control_m[] = {UNK, DISP, M("Run", MC_Run, 0), M("Pause", MC_Pause, 0), M("Stop", MC_Stop, 0),
    M("GetState", MC_GetState, 2), M("RenderFile", ok1, 1), M("AddSourceFilter", ok2, 2), M("get_FilterCollection", ok1, 1),
    M("get_RegFilterCollection", ok1, 1), M("StopWhenReady", MC_Stop, 0)};
static const ComMethod event_m[] = {UNK, DISP, M("GetEventHandle", ME_GetEventHandle, 1), M("GetEvent", ME_GetEvent, 4),
    M("WaitForCompletion", ME_WaitForCompletion, 2), M("CancelDefaultHandling", ok1, 1), M("RestoreDefaultHandling", ok1, 1),
    M("FreeEventParams", ok3, 3), M("SetNotifyWindow", ok3, 3), M("SetNotifyFlags", ok1, 1), M("GetNotifyFlags", ok1, 1)};
static const ComMethod audio_m[] = {UNK, DISP, M("put_Volume", BA_put_Volume, 1), M("get_Volume", BA_get_Volume, 1),
    M("put_Balance", ok1, 1), M("get_Balance", BA_get_Balance, 1)};
static const ComMethod seeking_m[] = {UNK, M("GetCapabilities", MS_GetCaps, 1), M("CheckCapabilities", ok1, 1),
    M("IsFormatSupported", ok1, 1), M("QueryPreferredFormat", MS_GetTimeFormat, 1), M("GetTimeFormat", MS_GetTimeFormat, 1),
    M("IsUsingTimeFormat", ok1, 1), M("SetTimeFormat", ok1, 1), M("GetDuration", MS_GetDuration, 1),
    M("GetStopPosition", MS_GetStopPosition, 1), M("GetCurrentPosition", MS_GetCurrentPosition, 1),
    M("ConvertTimeFormat", ok5, 5), M("SetPositions", MS_SetPositions, 4), M("GetPositions", MS_GetPositions, 2),
    M("GetAvailable", ok2, 2), M("SetRate", ok2, 2), M("GetRate", MS_GetRate, 1), M("GetPreroll", ok1, 1)};
static const ComMethod position_m[] = {UNK, DISP, M("get_Duration", MP_get_Duration, 1), M("put_CurrentPosition", MP_put_CurrentPosition, 2),
    M("get_CurrentPosition", MP_get_CurrentPosition, 1), M("get_StopTime", MP_get_Duration, 1), M("put_StopTime", ok2, 2),
    M("get_PrerollTime", ok1, 1), M("put_PrerollTime", ok2, 2), M("put_Rate", ok2, 2), M("get_Rate", MS_GetRate, 1),
    M("CanSeekForward", ok1, 1), M("CanSeekBackward", ok1, 1)};

// called by the CoCreateInstance shim for CLSID_FilterGraph
uint32_t dshow_create_filtergraph(uint32_t iid) {
    if (!graphs) {
        graphs = [NSMutableDictionary dictionary];
#define V(i, m) vt[i] = com_vtable(#m, m, (int)(sizeof m / sizeof *m))
        V(I_GRAPH, graph_m); V(I_CONTROL, control_m); V(I_EVENT, event_m); V(I_AUDIO, audio_m); V(I_SEEKING, seeking_m); V(I_POSITION, position_m);
    }
    uint32_t gid = next_gid++;
    DSGraph *g = [DSGraph new];
    g.volume = 0;
    graphs[@(gid)] = g;
    (void)iid;
    return iface(g, gid, I_GRAPH);
}
