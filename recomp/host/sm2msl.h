// D3D9 shader bytecode (vs_1_1 .. vs_3_0, ps_2_0 .. ps_3_0) -> Metal Shading Language.
#pragma once
#include <stddef.h>
#include <stdint.h>

enum { SEM_POSITION = 0, SEM_BLENDWEIGHT, SEM_BLENDINDICES, SEM_NORMAL, SEM_PSIZE, SEM_TEXCOORD, SEM_TANGENT,
       SEM_BINORMAL, SEM_TESSFACTOR, SEM_POSITIONT, SEM_COLOR, SEM_FOG, SEM_DEPTH, SEM_SAMPLE };

typedef struct {
    int is_ps, major, minor;
    // vertex shader inputs: v register -> (usage, index); -1 = unused
    int8_t in_usage[16], in_index[16];
    // interpolants: semantic keys (usage << 4 | index) written by a VS / read by a PS
    uint16_t io_keys[16]; int n_io;
    uint32_t samplers;           // bitmask of s# used
    uint8_t sampler_dim[16];     // 2 = 2D, 3 = cube, 4 = volume
    int writes_depth, uses_relative, max_const;
    int n_color_out;             // ps: highest oC# + 1
    uint32_t depth_mask_in;      // INPUT to sm_translate: samplers bound to depth textures (hardware PCF)
} SMInfo;

// Translate `tokens` (ending with 0x0000FFFF). `extra_out` (VS only) lists interpolant keys the
// paired PS reads that this VS does not write; they are emitted as zero so the stages link.
// Returns a malloc'd MSL string or NULL with an error message in `err`.
char *sm_translate(const uint32_t *tokens, size_t ntok, SMInfo *info, const uint16_t *extra_out, int n_extra,
                   char *err, size_t errlen);

// Fills `info` without generating code (reflection only).
int sm_reflect(const uint32_t *tokens, size_t ntok, SMInfo *info, char *err, size_t errlen);
