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

#include "dev/video/vterm.h"

#include "common/circbuf.h"
#include "common/kprintf.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"

#define TEST_WIDTH 10
#define TEST_HEIGHT 5

static void reset_video(video_t* video) {
  for (int i = 0; i < video->width * video->height; ++i)
    video->videoram[i] = (' ' << 8) | VGA_DEFAULT_ATTR;
}

static void basic_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: basic test");
  int x = 5, y = 5;
  vterm_clear(vt);
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  vterm_puts(vt, "abc", 3);
  KEXPECT_EQ('a', video_getc(video, 0, 0));
  KEXPECT_EQ('b', video_getc(video, 0, 1));
  KEXPECT_EQ('c', video_getc(video, 0, 2));
  KEXPECT_EQ(' ', video_getc(video, 0, 3));

  x = y = 5;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(3, x);
  KEXPECT_EQ(0, y);

  vterm_puts(vt, "de", 2);
  KEXPECT_EQ('a', video_getc(video, 0, 0));
  KEXPECT_EQ('b', video_getc(video, 0, 1));
  KEXPECT_EQ('c', video_getc(video, 0, 2));
  KEXPECT_EQ('d', video_getc(video, 0, 3));
  KEXPECT_EQ('e', video_getc(video, 0, 4));
  KEXPECT_EQ(' ', video_getc(video, 0, 5));

  x = y = 5;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(5, x);
  KEXPECT_EQ(0, y);
}

static void reset(vterm_t* vt, int row, int col) {
  vterm_clear(vt);
  for (int i = 0; i < row * TEST_WIDTH + col; ++i)
    vterm_putc(vt, ' ');
}

static void do_vterm_puts(vterm_t* vt, const char* s) {
  vterm_puts(vt, s, kstrlen(s));
}

static void ansi_escape_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: ignores invalid ANSI escape sequence");
  vterm_clear(vt);
  do_vterm_puts(vt, "ab\x1b" "[5x" "\x1b[?2K" "cd");
  KEXPECT_EQ('a', video_getc(video, 0, 0));
  KEXPECT_EQ('b', video_getc(video, 0, 1));
  KEXPECT_EQ('c', video_getc(video, 0, 2));
  KEXPECT_EQ('d', video_getc(video, 0, 3));
  KEXPECT_EQ(' ', video_getc(video, 0, 4));

  KTEST_BEGIN("vterm: ANSI color escape sequence");
  vterm_clear(vt);
  vterm_puts(vt, "ab\x1b" "[31mcd\x1b" "[0me", 14);
  KEXPECT_EQ('a', video_getc(video, 0, 0));
  KEXPECT_EQ(VGA_DEFAULT_ATTR, video_get_attr(video, 0, 0));
  KEXPECT_EQ('b', video_getc(video, 0, 1));
  KEXPECT_EQ(VGA_DEFAULT_ATTR, video_get_attr(video, 0, 1));
  KEXPECT_EQ('c', video_getc(video, 0, 2));
  KEXPECT_EQ(video_mk_attr(VGA_RED, VGA_BLACK), video_get_attr(video, 0, 2));
  KEXPECT_EQ('d', video_getc(video, 0, 3));
  KEXPECT_EQ(video_mk_attr(VGA_RED, VGA_BLACK), video_get_attr(video, 0, 3));
  KEXPECT_EQ('e', video_getc(video, 0, 4));
  KEXPECT_EQ(VGA_DEFAULT_ATTR, video_get_attr(video, 0, 4));


  KTEST_BEGIN("vterm: cursor up escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2A");
  int x = 5, y = 5;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN("vterm: cursor up escape sequence (clamp to edge)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[7A");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(0, y);
  do_vterm_puts(vt, "\x1b[7A");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: cursor up escape sequence (default is 1)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[A");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(2, y);

  KTEST_BEGIN("vterm: cursor up escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[5000A");
  do_vterm_puts(vt, "\x1b[-3A");
  do_vterm_puts(vt, "\x1b[0A");
  do_vterm_puts(vt, "\x1b[1;2A");
  do_vterm_puts(vt, "\x1b[;2A");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);


  KTEST_BEGIN("vterm: cursor down escape sequence");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[2B");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor down escape sequence (clamp to edge)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[7B");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(4, y);
  do_vterm_puts(vt, "\x1b[7B");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(4, y);

  KTEST_BEGIN("vterm: cursor down escape sequence (default is 1)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[B");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(2, y);

  KTEST_BEGIN("vterm: cursor down escape sequence (invalid)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[5000B");
  do_vterm_puts(vt, "\x1b[-3B");
  do_vterm_puts(vt, "\x1b[0B");
  do_vterm_puts(vt, "\x1b[1;2B");
  do_vterm_puts(vt, "\x1b[;2B");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(1, y);


  KTEST_BEGIN("vterm: cursor forwards escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2C");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor forwards escape sequence (clamp to edge)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[9C");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(9, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[9C");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(9, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor forwards escape sequence (default is 1)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[C");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(5, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor forwards escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[5000C");
  do_vterm_puts(vt, "\x1b[-3C");
  do_vterm_puts(vt, "\x1b[0C");
  do_vterm_puts(vt, "\x1b[1;2C");
  do_vterm_puts(vt, "\x1b[;2C");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);


  KTEST_BEGIN("vterm: cursor backwards escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2D");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(2, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor backwards escape sequence (clamp to edge)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[9D");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[9D");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor backwards escape sequence (default is 1)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[D");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(3, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor backwards escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[5000D");
  do_vterm_puts(vt, "\x1b[-3D");
  do_vterm_puts(vt, "\x1b[0D");
  do_vterm_puts(vt, "\x1b[1;2D");
  do_vterm_puts(vt, "\x1b[;2D");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);


  KTEST_BEGIN("vterm: cursor beginning of line N down escape sequence");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[2E");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: cursor beginning of line N down escape sequence (clamp to edge)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[7E");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(4, y);
  do_vterm_puts(vt, "\x1b[7E");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(4, y);

  KTEST_BEGIN("vterm: cursor beginning of line N down escape sequence (default is 1)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[E");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(2, y);

  KTEST_BEGIN("vterm: cursor beginning of line N down escape sequence (invalid)");
  reset(vt, 1, 4);
  do_vterm_puts(vt, "\x1b[5000E");
  do_vterm_puts(vt, "\x1b[-3E");
  do_vterm_puts(vt, "\x1b[1;2E");
  do_vterm_puts(vt, "\x1b[;2E");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(1, y);


  KTEST_BEGIN("vterm: cursor beginning of line N up escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2F");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN("vterm: cursor beginning of line N up escape sequence (clamp to edge)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[7F");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);
  do_vterm_puts(vt, "\x1b[7F");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: cursor beginning of line N up escape sequence (default is 1)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[F");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(2, y);

  KTEST_BEGIN("vterm: cursor beginning of line N up escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[5000F");
  do_vterm_puts(vt, "\x1b[-3F");
  do_vterm_puts(vt, "\x1b[1;2F");
  do_vterm_puts(vt, "\x1b[;2F");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);


  KTEST_BEGIN("vterm: set cursor column escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[7G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[1G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: set cursor column escape sequence (default is 1)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: set cursor column escape sequence (too low)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[0G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: set cursor column escape sequence (too high)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[200G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(TEST_WIDTH - 1, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: set cursor column escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[7;8G");
  do_vterm_puts(vt, "\x1b[;7G");
  do_vterm_puts(vt, "\x1b[7;G");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);



  KTEST_BEGIN("vterm: set cursor position escape sequence");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2;8H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(7, x);
  KEXPECT_EQ(1, y);
  do_vterm_puts(vt, "\x1b[1;1H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (default row)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[;8H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(7, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (default col)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2;H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (default col B)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (default row/col)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (default row/col B)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[;H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (row out of bounds)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[50;8H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(7, x);
  KEXPECT_EQ(TEST_HEIGHT - 1, y);
  do_vterm_puts(vt, "\x1b[0;8H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(7, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (col out of bounds)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[2;50H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(TEST_WIDTH - 1, x);
  KEXPECT_EQ(1, y);
  do_vterm_puts(vt, "\x1b[2;0H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN(
      "vterm: set cursor position escape sequence (row and col out of bounds)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[50;50H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(TEST_WIDTH - 1, x);
  KEXPECT_EQ(TEST_HEIGHT - 1, y);
  do_vterm_puts(vt, "\x1b[0;0H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (invalid)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[;;H");
  do_vterm_puts(vt, "\x1b[5;2;H");
  do_vterm_puts(vt, "\x1b[5;2;3H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: set cursor position escape sequence (alternate seq)");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[5;8f");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(7, x);
  KEXPECT_EQ(4, y);
}

static const char* get_line(video_t* video, int row) {
  static char line[TEST_WIDTH + 1];
  for (int i = 0; i < TEST_WIDTH; ++i)
    line[i] = video_getc(video, row, i);
  line[TEST_WIDTH] = '\0';
  return line;
}

static const char* get_line_attr(video_t* video, int row) {
  static char line[TEST_WIDTH + 1];
  for (int i = 0; i < TEST_WIDTH; ++i)
    line[i] = (video_get_attr(video, row, i) == VGA_DEFAULT_ATTR) ? 'D' : 'x';
  line[TEST_WIDTH] = '\0';
  return line;
}

static void reset_and_fill(vterm_t* vt, char c, int row, int col) {
  vterm_clear(vt);
  vterm_puts(vt, "\x1b[m", 3);
  for (int i = 0; i < TEST_WIDTH * TEST_HEIGHT; ++i)
    vterm_putc(vt, c);
  char buf[100];
  ksprintf(buf, "\x1b[%d;%dH", row + 1, col + 1);
  do_vterm_puts(vt, buf);
  vterm_puts(vt, "\x1b[31m", 5);
}

static void ansi_erase_screen_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: erase to end of screen");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[0J");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 0));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 1));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("AAAA      ", get_line(video, 3));
  KEXPECT_STREQ("          ", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 0));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 1));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("DDDDxxxxxx", get_line_attr(video, 3));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 4));
  int x, y;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase to end of screen (default)");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[J");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 0));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 1));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("AAAA      ", get_line(video, 3));
  KEXPECT_STREQ("          ", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 0));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 1));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("DDDDxxxxxx", get_line_attr(video, 3));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase to beginning of screen");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[1J");
  KEXPECT_STREQ("          ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  KEXPECT_STREQ("          ", get_line(video, 2));
  KEXPECT_STREQ("     AAAAA", get_line(video, 3));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 4));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 0));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 1));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 2));
  KEXPECT_STREQ("xxxxxDDDDD", get_line_attr(video, 3));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase whole screen");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[2J");
  for (int i = 0; i < 5; ++i) {
    KEXPECT_STREQ("          ", get_line(video, i));
    KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, i));
  }
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase screen with invalid args");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[3J");
  do_vterm_puts(vt, "\x1b[13J");
  do_vterm_puts(vt, "\x1b[2;J");
  do_vterm_puts(vt, "\x1b[;J");
  do_vterm_puts(vt, "\x1b[;3;10J");
  for (int i = 0; i < 5; ++i) {
    KEXPECT_STREQ("AAAAAAAAAA", get_line(video, i));
    KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, i));
  }
}

static void ansi_erase_line_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: erase to end of line");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[0K");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("AAAA      ", get_line(video, 3));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("DDDDxxxxxx", get_line_attr(video, 3));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 4));
  int x, y;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase to end of line (default)");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[K");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("AAAA      ", get_line(video, 3));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("DDDDxxxxxx", get_line_attr(video, 3));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase to beginning of line");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[1K");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("     AAAAA", get_line(video, 3));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("xxxxxDDDDD", get_line_attr(video, 3));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase whole line");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[2K");
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 2));
  KEXPECT_STREQ("          ", get_line(video, 3));
  KEXPECT_STREQ("AAAAAAAAAA", get_line(video, 4));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 2));
  KEXPECT_STREQ("xxxxxxxxxx", get_line_attr(video, 3));
  KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  KTEST_BEGIN("vterm: erase line with invalid args");
  reset_and_fill(vt, 'A', 3, 4);
  do_vterm_puts(vt, "\x1b[3K");
  do_vterm_puts(vt, "\x1b[13K");
  do_vterm_puts(vt, "\x1b[2;K");
  do_vterm_puts(vt, "\x1b[;K");
  do_vterm_puts(vt, "\x1b[;3;10K");
  for (int i = 0; i < 5; ++i) {
    KEXPECT_STREQ("AAAAAAAAAA", get_line(video, i));
    KEXPECT_STREQ("DDDDDDDDDD", get_line_attr(video, i));
  }
}

static void ansi_save_cursor_test(video_t* video, vterm_t* vt) {
  int x, y;

  KTEST_BEGIN("vterm: default cursor restore position");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: save cursor position");
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[s");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[2;7H");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(1, y);
  do_vterm_puts(vt, "\x1b[u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[2;7H\x1b[u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);
  do_vterm_puts(vt, "\x1b[2;7H\x1b[s\x1b[H\x1b[u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(1, y);

  KTEST_BEGIN("vterm: save/restore cursor position (invalid)");
  do_vterm_puts(vt, "\x1b[4;5H");
  do_vterm_puts(vt, "\x1b[;s");
  do_vterm_puts(vt, "\x1b[1s");
  do_vterm_puts(vt, "\x1b[1;2s");
  do_vterm_puts(vt, "\x1b[1u");
  do_vterm_puts(vt, "\x1b[;2u");
  do_vterm_puts(vt, "\x1b[;u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);

  do_vterm_puts(vt, "\x1b[u");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(6, x);
  KEXPECT_EQ(1, y);
}

static void newline_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: newline handling test");
  vterm_clear(vt);
  do_vterm_puts(vt, "abc\nde\n\nf");
  KEXPECT_STREQ("abc       ", get_line(video, 0));
  KEXPECT_STREQ("de        ", get_line(video, 1));
  KEXPECT_STREQ("          ", get_line(video, 2));
  KEXPECT_STREQ("f         ", get_line(video, 3));

  KTEST_BEGIN("vterm: newline scrolling test");
  vterm_clear(vt);
  do_vterm_puts(vt, "abc\nde\n\nfg\nh\ni");
  KEXPECT_STREQ("de        ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  KEXPECT_STREQ("fg        ", get_line(video, 2));
  KEXPECT_STREQ("h         ", get_line(video, 3));
  KEXPECT_STREQ("i         ", get_line(video, 4));
}

static void backspace_test(video_t* video, vterm_t* vt) {
  int x, y;
  KTEST_BEGIN("vterm: basic backspace test");
  vterm_clear(vt);
  do_vterm_puts(vt, "abcd\b");
  KEXPECT_STREQ("abcd      ", get_line(video, 0));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(3, x);
  KEXPECT_EQ(0, y);
  do_vterm_puts(vt, "X");
  KEXPECT_STREQ("abcX      ", get_line(video, 0));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(0, y);

  KTEST_BEGIN("vterm: backspace across line test");
  vterm_clear(vt);
  do_vterm_puts(vt, "abcdefghijkl");
  KEXPECT_STREQ("abcdefghij", get_line(video, 0));
  KEXPECT_STREQ("kl        ", get_line(video, 1));
  do_vterm_puts(vt, "\b \b");
  KEXPECT_STREQ("k         ", get_line(video, 1));
  do_vterm_puts(vt, "\b \b");
  KEXPECT_STREQ("abcdefghij", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  do_vterm_puts(vt, "\b \b");
  KEXPECT_STREQ("abcdefghi ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(9, x);
  KEXPECT_EQ(0, y);
}

static void implicit_scroll_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: wrapping scroll test");
  vterm_clear(vt);
  do_vterm_puts(vt, "abcd\n\n\n\n");
  do_vterm_puts(vt, "0123456789ABCDE");
  KEXPECT_STREQ("          ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  KEXPECT_STREQ("          ", get_line(video, 2));
  KEXPECT_STREQ("0123456789", get_line(video, 3));
  KEXPECT_STREQ("ABCDE     ", get_line(video, 4));
}

static void wrap_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: basic wrap test");
  vterm_clear(vt);
  do_vterm_puts(vt, "0123456789A");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("A         ", get_line(video, 1));
  int x, y;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(1, x);
  KEXPECT_EQ(1, y);


  // Test that we don't wrap until the first letter of the next line is typed.
  KTEST_BEGIN("vterm: doesn't wrap on last letter");
  vterm_clear(vt);
  do_vterm_puts(vt, "0123456789");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));

  // The cursor should be on the right margin.
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(0, y);
  // TODO(aoates): verify video cursor position.
  do_vterm_puts(vt, "A");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("A         ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(1, x);
  KEXPECT_EQ(1, y);


  KTEST_BEGIN("vterm: backspace on right margin");
  vterm_clear(vt);
  do_vterm_puts(vt, "0123456789");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(0, y);

  do_vterm_puts(vt, "\b \b");
  KEXPECT_STREQ("012345678 ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  // TODO(aoates): verify video cursor position.
  KEXPECT_EQ(9, x);
  KEXPECT_EQ(0, y);


  // Test that if we type a newline while the cursor is on the right margin (the
  // current line is full), we go to the next line but don't consume a
  // character.
  KTEST_BEGIN("vterm: newline while on right margin");
  vterm_clear(vt);
  do_vterm_puts(vt, "0123456789");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(0, y);
  // TODO(aoates): verify video cursor position.
  do_vterm_puts(vt, "\n");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);
  do_vterm_puts(vt, "A");
  KEXPECT_STREQ("0123456789", get_line(video, 0));
  KEXPECT_STREQ("A         ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(1, x);
  KEXPECT_EQ(1, y);


  KTEST_BEGIN("vterm: backspace across silent right margin newline");
  vterm_clear(vt);
  do_vterm_puts(vt, "0123456789\n");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(1, y);

  do_vterm_puts(vt, "\b \b");
  KEXPECT_STREQ("012345678 ", get_line(video, 0));
  KEXPECT_STREQ("          ", get_line(video, 1));
  vterm_get_cursor(vt, &x, &y);
  // TODO(aoates): verify video cursor position.
  KEXPECT_EQ(9, x);
  KEXPECT_EQ(0, y);


  // Test that we don't scroll when we hit the last character of the last line.
  KTEST_BEGIN("vterm: doesn't scroll on last letter");
  vterm_clear(vt);
  do_vterm_puts(vt, "x\ny\nz\n\n0123456789");
  KEXPECT_STREQ("x         ", get_line(video, 0));
  KEXPECT_STREQ("0123456789", get_line(video, 4));

  // The cursor should be on the right margin.
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(4, y);
  // TODO(aoates): verify video cursor position.
  do_vterm_puts(vt, "A");
  KEXPECT_STREQ("y         ", get_line(video, 0));
  KEXPECT_STREQ("0123456789", get_line(video, 3));
  KEXPECT_STREQ("A         ", get_line(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(1, x);
  KEXPECT_EQ(4, y);


  // As above, but typing a newline.
  KTEST_BEGIN("vterm: newline scroll on last letter");
  vterm_clear(vt);
  do_vterm_puts(vt, "x\ny\nz\n\n0123456789");
  KEXPECT_STREQ("x         ", get_line(video, 0));
  KEXPECT_STREQ("0123456789", get_line(video, 4));

  // The cursor should be on the right margin.
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(4, y);
  // TODO(aoates): verify video cursor position.
  do_vterm_puts(vt, "\n");
  KEXPECT_STREQ("y         ", get_line(video, 0));
  KEXPECT_STREQ("0123456789", get_line(video, 3));
  KEXPECT_STREQ("          ", get_line(video, 4));
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(4, y);
}

static void circbuf_putc(void* arg, char n) {
  circbuf_write((circbuf_t*)arg, &n, 1);
}

static void ansi_report_cursor_test(video_t* video, vterm_t* vt) {
  char buf[50];
  circbuf_t cbuf;
  circbuf_init(&cbuf, buf, 50);

  KTEST_BEGIN("vterm: report cursor (DSR) escape sequence");
  kmemset(buf, '\0', 50);
  vterm_set_sink(vt, &circbuf_putc, &cbuf);
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[6n");
  int x, y;
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);
  KEXPECT_EQ(6, cbuf.len);
  KEXPECT_EQ('\x1b', buf[0]);
  KEXPECT_STREQ("[4;5R", buf + 1);


  KTEST_BEGIN("vterm: report cursor (DSR) escape sequence at right margin");
  cbuf.len = cbuf.pos = 0;
  kmemset(buf, '\0', 50);
  reset(vt, 3, 4);
  do_vterm_puts(vt, "aaaaaa");
  do_vterm_puts(vt, "\x1b[6n");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(10, x);
  KEXPECT_EQ(3, y);
  KEXPECT_EQ(7, cbuf.len);
  KEXPECT_EQ('\x1b', buf[0]);
  KEXPECT_STREQ("[4;11R", buf + 1);


  KTEST_BEGIN("vterm: report cursor (DSR) escape sequence (invalid)");
  cbuf.len = cbuf.pos = 0;
  reset(vt, 3, 4);
  do_vterm_puts(vt, "\x1b[n");
  do_vterm_puts(vt, "\x1b[3n");
  do_vterm_puts(vt, "\x1b[7n");
  do_vterm_puts(vt, "\x1b[;n");
  do_vterm_puts(vt, "\x1b[6;n");
  vterm_get_cursor(vt, &x, &y);
  KEXPECT_EQ(4, x);
  KEXPECT_EQ(3, y);
  KEXPECT_EQ(0, cbuf.len);

  vterm_set_sink(vt, NULL, NULL);
}

static void cursor_visibility_test(video_t* video, vterm_t* vt) {
  KTEST_BEGIN("vterm: hide cursor escape sequence");
  do_vterm_puts(vt, "\x1b[?25l");
  // TODO(aoates): verify cursor is actually hidden.

  KTEST_BEGIN("vterm: show cursor escape sequence");
  do_vterm_puts(vt, "\x1b[?25h");
  // TODO(aoates): verify cursor is actually shown.

  KTEST_BEGIN("vterm: show/hide cursor escape sequence (invalid)");
  do_vterm_puts(vt, "\x1b[?24h");
  do_vterm_puts(vt, "\x1b[?24l");
  do_vterm_puts(vt, "\x1b[?h");
  do_vterm_puts(vt, "\x1b[?l");
  do_vterm_puts(vt, "\x1b[?25;l");
  do_vterm_puts(vt, "\x1b[?25;h");
  do_vterm_puts(vt, "\x1b[?25k");
  // TODO(aoates): verify cursor hasn't been changed.
}

// TODO(aoates): things to test,
//  - clear and redraw

void vterm_test(void) {
  KTEST_SUITE_BEGIN("vterm test");
  video_t test_video;
  test_video.videoram = kmalloc(sizeof(uint16_t) * TEST_WIDTH * TEST_HEIGHT);
  test_video.width = TEST_WIDTH;
  test_video.height = TEST_HEIGHT;
  reset_video(&test_video);

  vterm_t* vt = vterm_create(&test_video);
  basic_test(&test_video, vt);
  ansi_escape_test(&test_video, vt);
  ansi_erase_screen_test(&test_video, vt);
  ansi_erase_line_test(&test_video, vt);
  ansi_save_cursor_test(&test_video, vt);
  newline_test(&test_video, vt);
  backspace_test(&test_video, vt);
  implicit_scroll_test(&test_video, vt);
  wrap_test(&test_video, vt);
  ansi_report_cursor_test(&test_video, vt);
  cursor_visibility_test(&test_video, vt);

  vterm_destroy(vt);
  kfree(test_video.videoram);
}
