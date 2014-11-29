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
#include "memory/kmalloc.h"

struct vterm {
  video_t* video;
  int cursor_x, cursor_y;

  // Cache the video's dimensions.
  int vwidth, vheight;

  // The text of each line on the display.
  uint8_t** line_text;

  // The line-length of each line on the display.
  int* line_length;
};

// Scroll down a given nmuber of lines.
static void scroll(vterm_t* t, int amt) {
  KASSERT(amt >= 0);

  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      uint8_t newc = ' ';
      if (row + amt < t->vheight) {
        newc = video_getc(t->video, row + amt, col);
      }
      video_setc(t->video, row, col, newc, VGA_DEFAULT_ATTR);
      t->line_text[row][col] = newc;
    }

    int new_length = 0;
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

  term->line_length = (int*)kmalloc(sizeof(int) * term->vheight);
  for (int i = 0; i < term->vheight; i++) {
    term->line_length[i] = 0;
  }

  term->line_text = (uint8_t**)kmalloc(
      sizeof(uint8_t*) * term->vheight);
  for (int i = 0; i < term->vheight; i++) {
    term->line_text[i] = (uint8_t*)kmalloc(
        sizeof(uint8_t) * term->vwidth);
    for (int j = 0; j < term->vwidth; j++) {
      term->line_text[i][j] = ' ';
    }
  }

  return term;
}

// Sets a character in the video and in the vterm's stored version.
static inline void vterm_setc(vterm_t* t, int row,
                              int col, uint8_t c) {
  video_setc(t->video, row, col, c, VGA_DEFAULT_ATTR);
  t->line_text[row][col] = c;
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
    vterm_setc(t, t->cursor_y, t->cursor_x, ' ');
  } else {
    // Printable character.
    vterm_setc(t, t->cursor_y, t->cursor_x, c);
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
  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      t->line_text[row][col] = ' ';
    }
  }

  t->cursor_x = t->cursor_y = 0;
  video_move_cursor(t->video, t->cursor_y, t->cursor_x);
}

void vterm_redraw(vterm_t* t) {
  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      video_setc(t->video, row, col, t->line_text[row][col], VGA_DEFAULT_ATTR);
    }
  }
  video_move_cursor(t->video, t->cursor_y, t->cursor_x);
}
