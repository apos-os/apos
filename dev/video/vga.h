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

// Basic driver for built-in VGA display.  Probably wouldn't work on real
// hardware.
#ifndef DEV_VIDEO_VIDEO_H
#define DEV_VIDEO_VIDEO_H

#include <stdint.h>

enum video_color {
  VGA_BLACK = 0,
  VGA_BLUE = 1,
  VGA_GREEN = 2,
  VGA_CYAN = 3,
  VGA_RED = 4,
  VGA_MAGENTA = 5,
  VGA_YELLOW = 6,
  VGA_WHITE = 7,
};

#define VGA_NORMAL 0x00
#define VGA_BRIGHT 0x08

#define VGA_DEFAULT_ATTR 0x07

// Attributes of a cell on the display.
typedef uint8_t video_attr_t;

static inline video_attr_t video_mk_attr(int fg, int bg) {
  return ((bg & 0x0F) << 4) | (fg & 0x0F);
}

static inline int video_attr_fg(video_attr_t attr) {
  return attr & 0x0F;
}

static inline int video_attr_bg(video_attr_t attr) {
  return (attr & 0xF0) >> 4;
}

typedef struct video video_t;

// Initialize the VGA subsystem.
void video_vga_init(void);

// Returns a video_t associated with the default display.
video_t* video_get_default(void);

// Return the width/height of the display.
int video_get_width(video_t* v);
int video_get_height(video_t* v);

// Sets the character at a given position on the display.
void video_setc(video_t* v, int row, int col, uint8_t c);
void video_set_attr(video_t* v, int row, int col, video_attr_t attr);

// Returns the character at the given position.
uint8_t video_getc(video_t* v, int row, int col);
video_attr_t video_get_attr(video_t* v, int row, int col);

// Clears the display.
void video_clear(video_t* v);

// Moves the cursor.
void video_move_cursor(video_t* v, int row, int col);

#endif
