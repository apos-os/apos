// Copyright 2014 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Basic video terminal that can output ASCII, handle backspace, etc.  It stores
// (and can restore) it's current state, allowing multiple video terminals to be
// multiplexed on a single video device.
#ifndef APOO_DEV_VIDEO_VTERM
#define APOO_DEV_VIDEO_VTERM

#include <stdint.h>
#include <stddef.h>

#include "dev/video/vga.h"

typedef struct vterm vterm_t;

// Create a vterm attached to the given video device.
vterm_t* vterm_create(video_t* v);

// Send a character to the vterm.
void vterm_putc(vterm_t* t, uint8_t c);

// char_sink_t version of the above.
static inline void vterm_putc_sink(void* arg, char c) {
  vterm_putc((vterm_t*)arg, (uint8_t)c);
}

// Send a string of characters to the vterm.
// TODO(aoates): update callers of vterm_putc() to use vterm_puts() when
// possible.
void vterm_puts(vterm_t* t, const char* s, size_t len);

// Clear the terminal.
void vterm_clear(vterm_t* t);

// Clear the screen and redraw the current state onto the video device.
void vterm_redraw(vterm_t* t);

// Get the cursor position of the terminal.
void vterm_get_cursor(vterm_t* t, int* x, int* y);

#endif
