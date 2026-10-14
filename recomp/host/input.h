#pragma once
#include <stdint.h>

// Shared input state fed by the window (real input) and by an input script (automation), read by
// the DirectInput shims. Thread-safe.
void input_key(int dik, int down);                 // DirectInput scancode (DIK_*)
void input_mouse_move(int dx, int dy);
void input_mouse_wheel(int dz);
void input_mouse_button(int b, int down);
void input_script_tick(uint64_t frame);
void input_frame_draws(uint64_t draws_this_frame);             // FNV_INPUT_SCRIPT: apply events due at this frame

// DirectInput side
void input_keyboard_state(uint8_t out[256]);
void input_mouse_state(int32_t *dx, int32_t *dy, int32_t *dz, uint8_t buttons[8]);   // deltas since last call
// buffered events: device 0 = keyboard, 1 = mouse. Returns 1 and fills (ofs, data) if one is pending.
int input_pop_event(int device, uint32_t *ofs, uint32_t *data, int peek_index);
int input_pending(int device);
int input_take_dump_request(void);
