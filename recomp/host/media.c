// Bink video + Vorbis (libvorbisfile) — M2 stubs: every open fails, so the game skips intro videos
// and falls back to silence for Vorbis-streamed music. M4: FFmpeg's bink decoder and native libvorbis.
#include <stdio.h>
#include "shims.h"

// binkw32 exports are stdcall: the @N decoration is the argument byte count
static void BinkSetSoundSystem_(CPU *c) { RET(c, 1, 2); }
static void BinkOpen_(CPU *c) { fprintf(stderr, "[bink] BinkOpen(%s) -> NULL (video playback not implemented yet)\n", GSTR(ARG(c, 0)) ? GSTR(ARG(c, 0)) : "?"); RET(c, 0, 2); }
static void BinkOpenDirectSound_(CPU *c) { RET(c, 0, 1); }
static void BinkClose_(CPU *c) { RET(c, 0, 1); }
static void BinkNextFrame_(CPU *c) { RET(c, 0, 1); }
static void BinkWait_(CPU *c) { RET(c, 0, 1); }
static void BinkPause_(CPU *c) { RET(c, 0, 2); }
static void BinkDoFrame_(CPU *c) { RET(c, 0, 1); }
static void BinkCopyToBufferRect_(CPU *c) { RET(c, 0, 11); }

// libvorbisfile exports are cdecl: the caller pops
static void ov_open_callbacks_(CPU *c) { fprintf(stderr, "[vorbis] ov_open_callbacks -> OV_ENOTVORBIS (not implemented yet)\n"); RET(c, (uint32_t)-132, 0); }
static void ov_clear_(CPU *c) { RET(c, 0, 0); }
static void ov_info_(CPU *c) { RET(c, 0, 0); }
static void ov_pcm_total_(CPU *c) { SETREG(c, R_EDX, 0); RET(c, 0, 0); }
static void ov_seekable_(CPU *c) { RET(c, 0, 0); }
static void ov_read_(CPU *c) { RET(c, 0, 0); }

const ShimTable media_shims = { (const Shim[]){
    {"_BinkSetSoundSystem@8", BinkSetSoundSystem_}, {"_BinkOpen@8", BinkOpen_}, {"_BinkOpenDirectSound@4", BinkOpenDirectSound_},
    {"_BinkClose@4", BinkClose_}, {"_BinkNextFrame@4", BinkNextFrame_}, {"_BinkWait@4", BinkWait_}, {"_BinkPause@8", BinkPause_},
    {"_BinkDoFrame@4", BinkDoFrame_}, {"_BinkCopyToBufferRect@44", BinkCopyToBufferRect_},
    {"ov_open_callbacks", ov_open_callbacks_}, {"ov_clear", ov_clear_}, {"ov_info", ov_info_}, {"ov_pcm_total", ov_pcm_total_},
    {"ov_seekable", ov_seekable_}, {"ov_read", ov_read_},
}, 15 };
