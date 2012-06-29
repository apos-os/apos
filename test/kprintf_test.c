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

void kprintf_test() {
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
  KEXPECT_STREQ("DEADBEEF", buf);

  // Test trailing %.
  ksprintf(buf, "abc%");
  KEXPECT_STREQ("abc", buf);

  // Put it all together.
  ksprintf(buf, "string:%s, int:%i, int:%i, hex:%x, percent:%%",
           "abc", 10, -10, 0xbeef);
  KEXPECT_STREQ("string:abc, int:10, int:-10, hex:BEEF, percent:%", buf);
}
