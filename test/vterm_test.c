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
  vterm_puts(vt, "ab\x1b" "[5xcd", 8);
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
}

// TODO(aoates): things to test,
//  - clear and redraw
//  - newlines
//  - backspace
//  - wrapping

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

  kfree(vt);
  kfree(test_video.videoram);
}
