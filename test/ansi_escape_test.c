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

#include "common/config.h"
#include "dev/video/ansi_escape.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"

#define CSI "\x1b["

void ansi_escape_test(void) {
  KTEST_SUITE_BEGIN("ANSI escape sequence parsing test");

  KTEST_BEGIN("FG color escape sequence");
  video_attr_t attr = video_mk_attr(VGA_BLUE | VGA_BRIGHT,
                                    VGA_RED | VGA_BRIGHT);
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "32m", 5, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_GREEN | VGA_BRIGHT, VGA_RED | VGA_BRIGHT), attr);

  KTEST_BEGIN("BG color escape sequence");
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "43m", 5, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_GREEN | VGA_BRIGHT, VGA_YELLOW | VGA_BRIGHT),
             attr);

  KTEST_BEGIN("Normal escape sequence");
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "0m", 4, &attr));
  KEXPECT_EQ(VGA_DEFAULT_ATTR, attr);

  KTEST_BEGIN("Bold escape sequence");
  attr = video_mk_attr(VGA_BLUE, VGA_RED);
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "1m", 4, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_BLUE | VGA_BRIGHT, VGA_RED | VGA_BRIGHT), attr);

  KTEST_BEGIN("Default FG color escape sequence");
  attr = video_mk_attr(VGA_BLUE, VGA_RED);
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "39m", 5, &attr));
  KEXPECT_EQ(video_mk_attr(video_attr_fg(VGA_DEFAULT_ATTR), VGA_RED), attr);

  KTEST_BEGIN("Default BG color escape sequence");
  attr = video_mk_attr(VGA_BLUE, VGA_RED);
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "49m", 5, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_BLUE, video_attr_bg(VGA_DEFAULT_ATTR)), attr);

  KTEST_BEGIN("Negative/reverse image escape sequence");
  attr = video_mk_attr(VGA_BLUE, VGA_RED | VGA_BRIGHT);
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "7m", 4, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_RED | VGA_BRIGHT, VGA_BLUE), attr);

  KTEST_BEGIN("Multiple attributes");
  attr = VGA_DEFAULT_ATTR;
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "34;1;46m", 10, &attr));
  KEXPECT_EQ(video_mk_attr(VGA_BLUE | VGA_BRIGHT, VGA_CYAN | VGA_BRIGHT), attr);

  const video_attr_t kStartAttr = video_mk_attr(VGA_BLUE, VGA_RED | VGA_BRIGHT);
  attr = kStartAttr;

  KTEST_BEGIN("Prefix (empty string)");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "34m", 0, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (just escape)");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "34m", 1, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (escape + '[')");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "34m", 2, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (CSI + num)");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "34m", 3, &attr));
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "34m", 4, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (CSI + num + ';')");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "3;", 4, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (CSI + num + ';' + num)");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "32;45", 7, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Prefix (CSI + num + ';' + num + ';')");
  KEXPECT_EQ(ANSI_PENDING, apply_ansi_escape(CSI "32;45;", 8, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Too long (valid prefix)");
  KEXPECT_EQ(20, ANSI_MAX_ESCAPE_SEQUENCE_LEN);  // If fails, update string.
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "32;33;34;35;36;42;43", 20,
                                             &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Too long (valid prefix)");
  KEXPECT_EQ(20, ANSI_MAX_ESCAPE_SEQUENCE_LEN);  // If fails, update string.
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "32;33;34;35;36;42;43", 21,
                                             &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Too long (really big number)");
  KEXPECT_EQ(20, ANSI_MAX_ESCAPE_SEQUENCE_LEN);  // If fails, update string.
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "3233343536424333212", 20,
                                             &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Exactly maximum length");
  KEXPECT_EQ(20, ANSI_MAX_ESCAPE_SEQUENCE_LEN);  // If fails, update string.
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "33;33;33;33;33;34m", 20,
                                             &attr));
  KEXPECT_EQ(VGA_BLUE, video_attr_fg(attr));
  attr = kStartAttr;

  KTEST_BEGIN("Number too long");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "1234m", 7, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Invalid first char");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("a", 1, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("a[", 2, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("a[3", 3, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("a[3m", 4, &attr));

  KTEST_BEGIN("Invalid second char");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("\x1b]", 2, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("\x1b]1", 3, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape("\x1b]1m", 4, &attr));

  KTEST_BEGIN("Invalid: embedded NULL");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "1\0m", 5, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Invalid: letters in the middle");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "am", 4, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "4am", 5, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "4;am", 6, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "4;+m", 6, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "4M", 4, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Invalid: too long but 'm' right after end");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "32;33;34;45;46;4;1m", 20,
                                             &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Invalid: unsupported SGR number ignored");
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "61m", 5, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("Invalid: invalid final letter");
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "37a", 5, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "37M", 5, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "37+", 5, &attr));
  KEXPECT_EQ(ANSI_INVALID, apply_ansi_escape(CSI "37\0", 5, &attr));
  KEXPECT_EQ(kStartAttr, attr);

  KTEST_BEGIN("each FG color");
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "30m", 5, &attr));
  KEXPECT_EQ(VGA_BLACK, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "31m", 5, &attr));
  KEXPECT_EQ(VGA_RED, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "32m", 5, &attr));
  KEXPECT_EQ(VGA_GREEN, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "33m", 5, &attr));
  KEXPECT_EQ(VGA_YELLOW, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "34m", 5, &attr));
  KEXPECT_EQ(VGA_BLUE, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "35m", 5, &attr));
  KEXPECT_EQ(VGA_MAGENTA, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "36m", 5, &attr));
  KEXPECT_EQ(VGA_CYAN, video_attr_fg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "37m", 5, &attr));
  KEXPECT_EQ(VGA_WHITE, video_attr_fg(attr));

  KTEST_BEGIN("each BG color");
  attr = 0x0;
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "40m", 5, &attr));
  KEXPECT_EQ(VGA_BLACK, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "41m", 5, &attr));
  KEXPECT_EQ(VGA_RED, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "42m", 5, &attr));
  KEXPECT_EQ(VGA_GREEN, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "43m", 5, &attr));
  KEXPECT_EQ(VGA_YELLOW, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "44m", 5, &attr));
  KEXPECT_EQ(VGA_BLUE, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "45m", 5, &attr));
  KEXPECT_EQ(VGA_MAGENTA, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "46m", 5, &attr));
  KEXPECT_EQ(VGA_CYAN, video_attr_bg(attr));
  KEXPECT_EQ(ANSI_SUCCESS, apply_ansi_escape(CSI "47m", 5, &attr));
  KEXPECT_EQ(VGA_WHITE, video_attr_bg(attr));

#if ENABLE_TERM_COLOR
  KTEST_BEGIN("Color rendering in vterm");
#define K(m) klogm(KL_TEST, INFO, m)
  for (int i = 0; i < 2; ++i) {
    K(i == 0 ? "Normal:\n" : "\nBright:\n");
    if (i == 1) K(CSI "1m");
    K(CSI "30mBLACK FG" CSI "0m      " CSI "37;40mBLACK BG" CSI "0m\n");
    K(CSI "31mRED FG" CSI "0m        " CSI "41mRED BG" CSI "0m\n");
    K(CSI "32mGREEN FG" CSI "0m      " CSI "42mGREEN BG" CSI "0m\n");
    K(CSI "33mYELLOW FG" CSI "0m     " CSI "43mYELLOW BG" CSI "0m\n");
    K(CSI "34mBLUE FG" CSI "0m       " CSI "44mBLUE BG" CSI "0m\n");
    K(CSI "35mMAGENTA FG" CSI "0m    " CSI "45mMAGENTA BG" CSI "0m\n");
    K(CSI "36mCYAN FG" CSI "0m       " CSI "46mCYAN BG" CSI "0m\n");
    K(CSI "37mWHITE FG" CSI "0m      " CSI "30;47mWHITE BG" CSI "0m\n");
    K(CSI "0m");
  }
#undef K
#endif
}
