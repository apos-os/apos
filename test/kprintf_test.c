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

#include "common/kstring.h"
#include "common/kprintf.h"
#include "test/ktest.h"

void kprintf_test(void) {
  KTEST_SUITE_BEGIN("kprintf");

  KTEST_BEGIN("ksprintf()");
  char buf[300];

  ksprintf(buf, "");
  KEXPECT_STREQ("", buf);

  ksprintf(buf, "abc");
  KEXPECT_STREQ("abc", buf);

  ksprintf(buf, "a");
  KEXPECT_STREQ("a", buf);

  ksprintf(buf, "a%%b");
  KEXPECT_STREQ("a%b", buf);

  ksprintf(buf, "%s", "arg1");
  KEXPECT_STREQ("arg1", buf);

  ksprintf(buf, "prefix%s", "arg1");
  KEXPECT_STREQ("prefixarg1", buf);

  ksprintf(buf, "%s%s%s", "arg1", "arg2", "arg3");
  KEXPECT_STREQ("arg1arg2arg3", buf);

  ksprintf(buf, "%s -- %s -- %s", "arg1", "arg2", "arg3");
  KEXPECT_STREQ("arg1 -- arg2 -- arg3", buf);

  // Test %d and %i.
  ksprintf(buf, "%d", 10);
  KEXPECT_STREQ("10", buf);

  ksprintf(buf, "%d %i %d", 99, 123, -459);
  KEXPECT_STREQ("99 123 -459", buf);

  // Test %u.
  ksprintf(buf, "%u  %u  %u", 0xFFFFFFFF, 0, 5);
  KEXPECT_STREQ("4294967295  0  5", buf);

  // Test %x.
  ksprintf(buf, "%x", 0x10);
  KEXPECT_STREQ("10", buf);

  ksprintf(buf, "%x", 0xDEADBEEF);
  KEXPECT_STREQ("deadbeef", buf);

  // Test %X.
  ksprintf(buf, "%X", 0x10);
  KEXPECT_STREQ("10", buf);

  ksprintf(buf, "%X %x", 0xDEADBEEF, 0xBAADF00D);
  KEXPECT_STREQ("DEADBEEF baadf00d", buf);

  // Test trailing %.
  ksprintf(buf, "abc%");
  KEXPECT_STREQ("abc", buf);

  // Put it all together.
  ksprintf(buf, "string:%s, int:%i, int:%i, hex:%X, percent:%%",
           "abc", 10, -10, 0xbeef);
  KEXPECT_STREQ("string:abc, int:10, int:-10, hex:BEEF, percent:%", buf);

  // Test field width.
  KTEST_BEGIN("ksprintf(): field width");
  ksprintf(buf, "%1d", 5);
  KEXPECT_STREQ("5", buf);
  ksprintf(buf, "%2d", 5);
  KEXPECT_STREQ(" 5", buf);
  ksprintf(buf, "%10d", 5);
  KEXPECT_STREQ("         5", buf);
  ksprintf(buf, "%2d", 123);
  KEXPECT_STREQ("123", buf);
  ksprintf(buf, "%2d", -123);
  KEXPECT_STREQ("-123", buf);
  ksprintf(buf, "%2d", -1);
  KEXPECT_STREQ("-1", buf);
  ksprintf(buf, "%3d", -1);
  KEXPECT_STREQ(" -1", buf);
  ksprintf(buf, "%3s", "a");
  KEXPECT_STREQ("  a", buf);
  ksprintf(buf, "%3x", 12);
  KEXPECT_STREQ("  c", buf);
  ksprintf(buf, "%3X", 12);
  KEXPECT_STREQ("  C", buf);
  ksprintf(buf, "%6x", 0xbeef);
  KEXPECT_STREQ("  beef", buf);
  ksprintf(buf, "%6X", 0xbeef);
  KEXPECT_STREQ("  BEEF", buf);
  ksprintf(buf, "%3s %4d %6x", "a", 12, 0xbeef);
  KEXPECT_STREQ("  a   12   beef", buf);
  ksprintf(buf, "%1d%1d%1d", 5, 5, 5);
  KEXPECT_STREQ("555", buf);
  ksprintf(buf, "%1d%1d%1d", -5, -5, -5);
  KEXPECT_STREQ("-5-5-5", buf);
  ksprintf(buf, "%5dabc%4ddef%3dhij", -5, -5, -5);
  KEXPECT_STREQ("   -5abc  -5def -5hij", buf);

  // Test the '0' flag.
  KTEST_BEGIN("ksprintf(): '0' flag");
  ksprintf(buf, "%0d", 5);
  KEXPECT_STREQ("5", buf);
  ksprintf(buf, "%0d", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "%01d", 5);
  KEXPECT_STREQ("5", buf);
  ksprintf(buf, "%03d", 5);
  KEXPECT_STREQ("005", buf);
  ksprintf(buf, "%03d", -5);
  KEXPECT_STREQ("-05", buf);
  ksprintf(buf, "%03d", -1234);
  KEXPECT_STREQ("-1234", buf);
  ksprintf(buf, "%06d", -123);
  KEXPECT_STREQ("-00123", buf);
  ksprintf(buf, "%06d", -1234);
  KEXPECT_STREQ("-01234", buf);
  ksprintf(buf, "%03i", 5);
  KEXPECT_STREQ("005", buf);
  ksprintf(buf, "%03u", 5);
  KEXPECT_STREQ("005", buf);
  ksprintf(buf, "%03x", 21);
  KEXPECT_STREQ("015", buf);
  ksprintf(buf, "%03X", 21);
  KEXPECT_STREQ("015", buf);
  ksprintf(buf, "%03s", "s");
  KEXPECT_STREQ("  s", buf);
  ksprintf(buf, "%03s", "ab");
  KEXPECT_STREQ(" ab", buf);
  ksprintf(buf, "%03s", "-1");
  KEXPECT_STREQ(" -1", buf);
  ksprintf(buf, "%05dabc%04ddef%03dhij", -5, -5, -5);
  KEXPECT_STREQ("-0005abc-005def-05hij", buf);

  // Test the ' ' flag.
  KTEST_BEGIN("ksprintf(): ' ' flag");
  ksprintf(buf, "% d", 5);
  KEXPECT_STREQ(" 5", buf);
  ksprintf(buf, "% d", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "% i", 5);
  KEXPECT_STREQ(" 5", buf);
  ksprintf(buf, "% i", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "% x", 12);
  KEXPECT_STREQ("c", buf);
  ksprintf(buf, "% X", 12);
  KEXPECT_STREQ("C", buf);
  ksprintf(buf, "% u", 12);
  KEXPECT_STREQ("12", buf);
  ksprintf(buf, "% s", "x");
  KEXPECT_STREQ("x", buf);
  ksprintf(buf, "% 05d", 15);
  KEXPECT_STREQ(" 0015", buf);
  ksprintf(buf, "% 05d", -15);
  KEXPECT_STREQ("-0015", buf);
  ksprintf(buf, "%0 5d", 15);
  KEXPECT_STREQ(" 0015", buf);
  ksprintf(buf, "%0 5d", -15);
  KEXPECT_STREQ("-0015", buf);
  ksprintf(buf, "%0 5d%0 3d% 3d% 4d", -15, 15, 15, -15);
  KEXPECT_STREQ("-0015 15 15 -15", buf);
  ksprintf(buf, "% d", 0);
  KEXPECT_STREQ(" 0", buf);
  ksprintf(buf, "% 05d", 0);
  KEXPECT_STREQ(" 0000", buf);
  ksprintf(buf, "% 05i", 0);
  KEXPECT_STREQ(" 0000", buf);


  // Test the '+' flag.
  KTEST_BEGIN("ksprintf(): '+' flag");
  ksprintf(buf, "%+d", 5);
  KEXPECT_STREQ("+5", buf);
  ksprintf(buf, "%+d", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "%+ d", 5);
  KEXPECT_STREQ("+5", buf);
  ksprintf(buf, "%+ d", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "% +d", 5);
  KEXPECT_STREQ("+5", buf);
  ksprintf(buf, "%+ 3d", 5);
  KEXPECT_STREQ(" +5", buf);
  ksprintf(buf, "% +3d", 5);
  KEXPECT_STREQ(" +5", buf);
  ksprintf(buf, "%+i", 5);
  KEXPECT_STREQ("+5", buf);
  ksprintf(buf, "%+i", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "%+x", 12);
  KEXPECT_STREQ("c", buf);
  ksprintf(buf, "%+X", 12);
  KEXPECT_STREQ("C", buf);
  ksprintf(buf, "%+u", 12);
  KEXPECT_STREQ("12", buf);
  ksprintf(buf, "%+s", "x");
  KEXPECT_STREQ("x", buf);
  ksprintf(buf, "%+05d", 15);
  KEXPECT_STREQ("+0015", buf);
  ksprintf(buf, "%+05d", -15);
  KEXPECT_STREQ("-0015", buf);
  ksprintf(buf, "%0+5d", 15);
  KEXPECT_STREQ("+0015", buf);
  ksprintf(buf, "%0+5d", -15);
  KEXPECT_STREQ("-0015", buf);
  ksprintf(buf, "%0+5d%0+3d%+3d%+4d", -15, 15, 15, -15);
  KEXPECT_STREQ("-0015+15+15 -15", buf);
  ksprintf(buf, "%+d", 0);
  KEXPECT_STREQ("+0", buf);
  ksprintf(buf, "%+05d", 0);
  KEXPECT_STREQ("+0000", buf);
  ksprintf(buf, "%+05i", 0);
  KEXPECT_STREQ("+0000", buf);

  // Test the '-' flag.
  KTEST_BEGIN("ksprintf(): '-' flag");
  ksprintf(buf, "%-d", 5);
  KEXPECT_STREQ("5", buf);
  ksprintf(buf, "%-d", -5);
  KEXPECT_STREQ("-5", buf);
  ksprintf(buf, "%-5d", 12);
  KEXPECT_STREQ("12   ", buf);
  ksprintf(buf, "%-5d", -12);
  KEXPECT_STREQ("-12  ", buf);
  ksprintf(buf, "%-5i", -12);
  KEXPECT_STREQ("-12  ", buf);
  ksprintf(buf, "%-5u", 12);
  KEXPECT_STREQ("12   ", buf);
  ksprintf(buf, "%-05u", 12);
  KEXPECT_STREQ("12   ", buf);
  ksprintf(buf, "%0-5u", 12);
  KEXPECT_STREQ("12   ", buf);
  ksprintf(buf, "%-05x", 36);
  KEXPECT_STREQ("24   ", buf);
  ksprintf(buf, "%-05X", 36);
  KEXPECT_STREQ("24   ", buf);
  ksprintf(buf, "%-+5d", 36);
  KEXPECT_STREQ("+36  ", buf);
  ksprintf(buf, "%-+2d", 36);
  KEXPECT_STREQ("+36", buf);
  ksprintf(buf, "%-+3d", 36);
  KEXPECT_STREQ("+36", buf);
  ksprintf(buf, "%- 5d", 36);
  KEXPECT_STREQ(" 36  ", buf);
  ksprintf(buf, "%-5s", "abc");
  KEXPECT_STREQ("abc  ", buf);
  ksprintf(buf, "%-2s", "abc");
  KEXPECT_STREQ("abc", buf);
}
