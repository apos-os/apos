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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "kmalloc.h"

struct vterm {
  video_t* video;
  uint32_t cursor_x, cursor_y;

  // Cache the video's dimensions.
  uint32_t vwidth, vheight;

  // The line-length of each line on the display.
  uint32_t* line_length;
};

// Scroll down a given nmuber of lines.
static void scroll(vterm_t* t, int amt) {
  KASSERT(amt >= 0);

  for (uint32_t row = 0; row < t->vheight; ++row) {
    for (uint32_t col = 0; col < t->vwidth; col++) {
      uint8_t newc = ' ';
      if (row + amt < t->vheight) {
        newc = video_getc(t->video, row + amt, col);
      }
      video_setc(t->video, row, col, newc);
    }

    uint32_t new_length = 0;
    if (row + amt < t->vheight) {
      new_length = t->line_length[row + amt];
    }
    t->line_length[row] = new_length;
  }
  t->cursor_y -= amt;
}

vterm_t* vterm_create(video_t* v) {
  vterm_t* term = (vterm_t*)kmalloc(sizeof(vterm_t));
  term->video = v;
  term->cursor_x = term->cursor_y = 0;
  term->vwidth = video_get_width(v);
  term->vheight = video_get_height(v);

  term->line_length = (uint32_t*)kmalloc(
      sizeof(uint32_t) * term->vheight);
  for (uint32_t i = 0; i < term->vheight; i++) {
    term->line_length[i] = 0;
  }

  return term;
}

void vterm_putc(vterm_t* t, uint8_t c) {
  // First calculate new cursor position if needed.
  if (c == '\r') {
    t->cursor_x = 0;
    t->line_length[t->cursor_y] = 0;
  } else if (c == '\f') {
    t->line_length[t->cursor_y] = t->cursor_x;
    t->cursor_y++;
  } else if (c == '\n') {
    // TODO(aoates): do we want to handle '\n'?
    t->line_length[t->cursor_y] = t->cursor_x;
    t->cursor_x = 0;
    t->cursor_y++;
  } else if (c == '\b') {
    if (t->cursor_x == 0 && t->cursor_y > 0) {
      if (t->line_length[t->cursor_y - 1] < t->vwidth) {
        t->cursor_x = t->line_length[t->cursor_y - 1];
      } else {
        // If the last line was full, just immediately delete the last character
        // on it.
        t->cursor_x = t->vwidth - 1;
      }
      t->cursor_y--;
    } else if (t->cursor_x > 0) {
      t->cursor_x--;
    }
    video_setc(t->video, t->cursor_y, t->cursor_x, ' ');
  } else {
    // Printable character.
    video_setc(t->video, t->cursor_y, t->cursor_x, c);
    t->cursor_x++;
  }

  // Wrap to next line if needed.
  if (t->cursor_x >= t->vwidth) {
    t->line_length[t->cursor_y] = t->cursor_x;
    t->cursor_x = 0;
    t->cursor_y++;
  }
  if (t->cursor_y >= t->vheight) {
    scroll(t, t->cursor_y - t->vheight + 1);
  }
  video_move_cursor(t->video, t->cursor_y, t->cursor_x);
}

void vterm_clear(vterm_t* t) {
  video_clear(t->video);
  t->cursor_x = t->cursor_y = 0;
  video_move_cursor(t->video, t->cursor_y, t->cursor_x);
}
