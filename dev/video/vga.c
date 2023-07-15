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

#include <stddef.h>
#include <stdint.h>

#include "arch/common/io.h"
#include "common/kassert.h"
#include "memory/memory.h"

#include "dev/video/vga.h"

#define MISC_OUTPUT_REG_READ 0x3CC
#define MISC_OUTPUT_REG_WRITE 0x3C2

#define MISC_OUTPUT_REG_IOAS 0x01

#define CRT_PORT_ADDR 0x3D4
#define CRT_PORT_DATA 0x3D5

#define CRT_START_ADDR 0x0A
#define CRT_START_CURSOR_DISABLE 0x20
#define CRT_START_CURSOR_START 0x0F

#define CRT_END_ADDR 0x0B
#define CRT_END_CURSOR_END 0x0F

#define CRT_CURSOR_LOW_ADDR  0x0F
#define CRT_CURSOR_HIGH_ADDR 0x0E

static video_t g_video;

void video_vga_init(void) {
  // Make sure our CRT controller register is in "color" mode.
  uint8_t c = inb(MISC_OUTPUT_REG_READ);
  c |= MISC_OUTPUT_REG_IOAS;
  outb(MISC_OUTPUT_REG_WRITE, c);

  video_show_cursor(NULL, true);
}

video_t* video_get_default(void) {
  g_video.videoram = (uint16_t*)(get_global_meminfo()->phys_map_start + 0xB8000);
  g_video.width = 80;
  g_video.height = 24;
  return &g_video;
}

void video_clear(video_t* v) {
  int i;
  for (i = 0; i < v->width * v->height; ++i) {
    v->videoram[i] = ' ' | (0x07 << 8);
  }
}

void video_move_cursor(video_t* v, int row, int col) {
  const uint16_t cursor_pos = row * v->width + col;

  uint8_t orig_addr = inb(CRT_PORT_ADDR);
  outb(CRT_PORT_ADDR, CRT_CURSOR_LOW_ADDR);
  outb(CRT_PORT_DATA, cursor_pos & 0xFF);
  outb(CRT_PORT_ADDR, CRT_CURSOR_HIGH_ADDR);
  outb(CRT_PORT_DATA, (cursor_pos >> 8) & 0xFF);
  outb(CRT_PORT_ADDR, orig_addr);
}

void video_show_cursor(video_t* v, bool visible) {
  uint8_t orig_addr = inb(CRT_PORT_ADDR);
  outb(CRT_PORT_ADDR, CRT_START_ADDR);
  uint8_t c = inb(CRT_PORT_DATA);
  if (visible)
    c &= ~CRT_START_CURSOR_DISABLE;
  else
    c |= CRT_START_CURSOR_DISABLE;
  outb(CRT_PORT_DATA, c);
  outb(CRT_PORT_ADDR, orig_addr);
}
