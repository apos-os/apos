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

#include <stdbool.h>
#include <stdint.h>

#include "common/config.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/math.h"
#include "dev/video/ansi_escape.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "memory/kmalloc.h"

struct vterm {
  video_t* video;

  // The cursor can be at any point on the screen, or on the "right margin",
  // where cursor_x == vwidth.  This is equivalent to the cursor being on the
  // first column of the next line, but doesn't cause scrolling.
  int cursor_x, cursor_y;
  int saved_cursor_x, saved_cursor_y;

  // Current video attributes.
  video_attr_t cattr;

  // Cache the video's dimensions.
  int vwidth, vheight;

  // The text of each line on the display.
  uint16_t** line_text;

#if ENABLE_TERM_COLOR
  // Current escape code we're working on.
  char escape_buffer[ANSI_MAX_ESCAPE_SEQUENCE_LEN];
  size_t escape_buffer_idx;
#endif

  char_sink_t sink;
  void* sink_arg;
};

__attribute__((always_inline))
static inline uint8_t line_text_c(vterm_t* t, int row, int col) {
  return t->line_text[row][col] & 0xFF;
}

__attribute__((always_inline))
static inline uint8_t line_text_attr(vterm_t* t, int row, int col) {
  return (t->line_text[row][col] & 0xFF00) >> 8;
}

__attribute__((always_inline))
static inline void set_line_text(vterm_t* t, int row, int col,
                                 uint8_t c, video_attr_t attr) {
  t->line_text[row][col] = c | (attr << 8);
}

// Sets a character in the video and in the vterm's stored version.
__attribute__((always_inline))
static inline void vterm_setc(vterm_t* t, int row, int col,
                              uint8_t c, video_attr_t attr) {
  video_setc(t->video, row, col, c, attr);
  set_line_text(t, row, col, c, attr);
}

static void update_video_cursor(vterm_t* t) {
  KASSERT_DBG(t->cursor_x <= t->vwidth);
  KASSERT_DBG(t->cursor_y < t->vheight);
  // Clamp the cursor, since we may be on the right margin.
  video_move_cursor(t->video, t->cursor_y, min(t->cursor_x, t->vwidth - 1));
}

// Scroll down a given nmuber of lines.
static void scroll(vterm_t* t, int amt) {
  KASSERT(amt >= 0);

  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      uint8_t newc = ' ';
      video_attr_t new_attr = t->cattr;
      if (row + amt < t->vheight) {
        newc = video_getc(t->video, row + amt, col);
        new_attr = video_get_attr(t->video, row + amt, col);
      }
      vterm_setc(t, row, col, newc, new_attr);
    }
  }
  t->cursor_y -= amt;
}

vterm_t* vterm_create(video_t* v) {
  vterm_t* term = (vterm_t*)kmalloc(sizeof(vterm_t));
  term->video = v;
  term->cursor_x = term->cursor_y = 0;
  term->saved_cursor_x = term->saved_cursor_y = 0;
  term->vwidth = video_get_width(v);
  term->vheight = video_get_height(v);
  term->cattr = VGA_DEFAULT_ATTR;
#if ENABLE_TERM_COLOR
  term->escape_buffer_idx = 0;
#endif
  term->sink = 0x0;
  term->sink_arg = 0x0;

  term->line_text = (uint16_t**)kmalloc(
      sizeof(uint16_t*) * term->vheight);
  for (int i = 0; i < term->vheight; i++) {
    term->line_text[i] = (uint16_t*)kmalloc(
        sizeof(uint16_t) * term->vwidth);
    for (int j = 0; j < term->vwidth; j++) {
      set_line_text(term, i, j, ' ', term->cattr);
    }
  }

  return term;
}

void vterm_destroy(vterm_t* t) {
  for (int i = 0; i < t->vheight; i++)
    kfree(t->line_text[i]);
  kfree(t->line_text);
  kfree(t);
}

void vterm_set_sink(vterm_t* t, char_sink_t sink, void* sink_arg) {
  t->sink = sink;
  t->sink_arg = sink_arg;
}

static int move_cursor_y(vterm_t* t, const ansi_seq_t* seq, int multiplier) {
  if (seq->num_codes > 1) return ANSI_INVALID;
  int offset = (seq->num_codes == 0) ? 1 : seq->codes[0];
  if (multiplier > 0)
    t->cursor_y += min(offset, t->vheight - t->cursor_y - 1);
  else
    t->cursor_y -= min(offset, t->cursor_y);

  return ANSI_SUCCESS;
}

static int move_cursor_x(vterm_t* t, const ansi_seq_t* seq, int multiplier) {
  if (seq->num_codes > 1) return ANSI_INVALID;
  int offset = (seq->num_codes == 0) ? 1 : seq->codes[0];
  if (multiplier > 0)
    t->cursor_x += min(offset, t->vwidth - t->cursor_x - 1);
  else
    t->cursor_x -= min(offset, t->cursor_x);

  return ANSI_SUCCESS;
}

static int move_cursor_y_to_first_col(vterm_t* t, const ansi_seq_t* seq,
                                      int multiplier) {
  int result = move_cursor_y(t, seq, multiplier);
  if (result != ANSI_SUCCESS) return result;
  t->cursor_x = 0;
  return ANSI_SUCCESS;
}

static int set_cursor_seq(vterm_t* t, const ansi_seq_t* seq) {
  if (seq->num_codes > 2) return ANSI_INVALID;
  int row = (seq->num_codes > 0) ? seq->codes[0] : -1;
  int col = (seq->num_codes > 1) ? seq->codes[1] : -1;
  if (row == -1) row = 1;
  if (col == -1) col = 1;
  row = max(1, min(t->vheight, row));
  col = max(1, min(t->vwidth, col));
  t->cursor_x = col - 1;
  t->cursor_y = row - 1;
  return ANSI_SUCCESS;
}

static int clear_seq(vterm_t* t, const ansi_seq_t* seq) {
  if (seq->num_codes > 1) return ANSI_INVALID;
  int mode = (seq->num_codes == 0) ? 0 : seq->codes[0];

  int start_row, end_row, start_col, end_col;
  switch (mode) {
    case 0:
      start_row = t->cursor_y;
      start_col = t->cursor_x;
      end_row = t->vheight;
      end_col = t->vwidth;
      break;

    case 1:
      start_row = start_col = 0;
      end_row = t->cursor_y + 1;
      end_col = t->cursor_x + 1;
      break;

    case 2:
      start_row = start_col = 0;
      end_row = t->vheight;
      end_col = t->vwidth;
      break;

    default:
      return ANSI_INVALID;
  }

  KASSERT_DBG(seq->final_letter == 'J' || seq->final_letter == 'K');
  if (seq->final_letter == 'K') {
    start_row = t->cursor_y;
    end_row = start_row + 1;
  }

  for (int row = start_row; row < end_row; row++) {
    for (int col = start_col; col < (row == end_row - 1 ? end_col : t->vwidth);
         col++) {
      vterm_setc(t, row, col, ' ', t->cattr);
    }
    start_col = 0;
  }
  return ANSI_SUCCESS;
}

static int save_restore_cursor_seq(vterm_t* t, const ansi_seq_t* seq) {
  if (seq->num_codes > 0) return ANSI_INVALID;

  KASSERT_DBG(seq->final_letter == 's' || seq->final_letter == 'u');
  if (seq->final_letter == 's') {
    t->saved_cursor_x = t->cursor_x;
    t->saved_cursor_y = t->cursor_y;
  } else {
    t->cursor_x = t->saved_cursor_x;
    t->cursor_y = t->saved_cursor_y;
  }

  return ANSI_SUCCESS;
}

static int report_cursor_seq(vterm_t* t, const ansi_seq_t* seq) {
  if (seq->num_codes != 1 || seq->codes[0] != 6) return ANSI_INVALID;
  if (t->sink) {
    char buf[20];
    ksprintf(buf, "\x1b[%d;%dR", t->cursor_y + 1, t->cursor_x+1);
    for (int i = 0; buf[i] != '\0'; ++i)
      t->sink(t->sink_arg, buf[i]);
  }
  return ANSI_SUCCESS;
}

static int try_ansi(vterm_t* t) {
  ansi_seq_t seq;
  int result = parse_ansi_escape(t->escape_buffer, t->escape_buffer_idx, &seq);
  if (result != ANSI_SUCCESS) return result;
  if (seq.priv) return ANSI_INVALID;

  int offset;
  switch (seq.final_letter) {
    case 'm':
      return apply_ansi_color(&seq, &t->cattr);

    case 'A':
      return move_cursor_y(t, &seq, -1);

    case 'B':
      return move_cursor_y(t, &seq, 1);

    case 'C':
      return move_cursor_x(t, &seq, 1);

    case 'D':
      return move_cursor_x(t, &seq, -1);

    case 'E':
      return move_cursor_y_to_first_col(t, &seq, 1);

    case 'F':
      return move_cursor_y_to_first_col(t, &seq, -1);

    case 'G':
      if (seq.num_codes > 1) return ANSI_INVALID;
      offset = (seq.num_codes == 0) ? 1 : seq.codes[0];
      offset = max(1, min(t->vwidth, offset));
      t->cursor_x = offset - 1;
      return ANSI_SUCCESS;

    case 'H':
    case 'f':
      return set_cursor_seq(t, &seq);

    case 'J':  // Clear screen.
    case 'K':  // Clear line.
      return clear_seq(t, &seq);

    case 's':
    case 'u':
      return save_restore_cursor_seq(t, &seq);

    case 'n':
      return report_cursor_seq(t, &seq);

    // TODO(aoates): handle hiding/showing the cursor.

    default:
      return ANSI_INVALID;
  }
}

// Wrap the cursor on the given terminal, scrolling if necessary.
static void do_wrap(vterm_t* t) {
  KASSERT_DBG(t->cursor_x <= t->vwidth);
  if (t->cursor_x >= t->vwidth) {
    t->cursor_x = 0;
    t->cursor_y++;
  }
  if (t->cursor_y >= t->vheight) {
    scroll(t, t->cursor_y - t->vheight + 1);
  }
  KASSERT_DBG(t->cursor_x < t->vwidth);
}

void vterm_putc(vterm_t* t, uint8_t c) {
#if ENABLE_TERM_COLOR
  if (c == '\x1b' || t->escape_buffer_idx > 0) {
    t->escape_buffer[t->escape_buffer_idx++] = c;
    int result = try_ansi(t);
    if (result == ANSI_SUCCESS || result == ANSI_INVALID) {
      // TODO(aoates): on error, handle the characters in the escape buffer
      // normally.
      t->escape_buffer_idx = 0;
    }
    return;
  }
#endif

  const bool is_newline = (c == '\r' || c == '\f' || c == '\n');
  if (is_newline) {
    // If we're on the right margin, don't do anything; the do_wrap() below will
    // wrap the line for us.
    if (t->cursor_x < t->vwidth) {
      t->cursor_x = 0;
      t->cursor_y++;
    }
  }

  do_wrap(t);

  // Note: both xterm and iterm seem to do this weird thing where they skip over
  // the second-to-last character in the line on backspace.  I don't see any
  // reason to emulate that, though.
  if (c == '\b') {
    if (t->cursor_x == 0 && t->cursor_y > 0) {
      t->cursor_x = t->vwidth - 1;
      t->cursor_y--;
    } else if (t->cursor_x > 0) {
      t->cursor_x--;
    }
    vterm_setc(t, t->cursor_y, t->cursor_x, ' ', t->cattr);
  } else if (!is_newline) {
    // Printable character.
    vterm_setc(t, t->cursor_y, t->cursor_x, c, t->cattr);
    t->cursor_x++;
  }

  update_video_cursor(t);
}

void vterm_puts(vterm_t* t, const char* s, size_t len) {
  for (size_t i = 0; i < len; ++i)
    vterm_putc(t, s[i]);
}

void vterm_clear(vterm_t* t) {
  video_clear(t->video);
  t->cattr = VGA_DEFAULT_ATTR;
  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      set_line_text(t, row, col, ' ', t->cattr);
    }
  }

  t->cursor_x = t->cursor_y = 0;
  update_video_cursor(t);
}

void vterm_redraw(vterm_t* t) {
  for (int row = 0; row < t->vheight; row++) {
    for (int col = 0; col < t->vwidth; col++) {
      video_setc(t->video, row, col, line_text_c(t, row, col),
                 line_text_attr(t, row, col));
    }
  }
  update_video_cursor(t);
}

void vterm_get_cursor(vterm_t* t, int* x, int* y) {
  *x = t->cursor_x;
  *y = t->cursor_y;
}
