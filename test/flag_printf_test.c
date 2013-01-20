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
#include "test/ktest.h"
#include "util/flag_printf.h"

static flag_spec_t FLAGS[] = {
  FLAG_SPEC_FLAG("F1", 0x1),
  FLAG_SPEC_FLAG2("F2", "NOT_F2", 0x2),
  FLAG_SPEC_FLAG("FFF3", 0x8),
  FLAG_SPEC_FLAG("FFFF4", 0x10),
  FLAG_SPEC_FIELD("T1", 0x60, 5),
  FLAG_SPEC_FIELD("T2", 0xF80, 7),
  FLAG_SPEC_END,
};

void flag_printf_test() {
  KTEST_SUITE_BEGIN("flag_printf()");

  char buf[100];
  int result;

  KTEST_BEGIN("empty test");
  result = flag_sprintf(buf, 0x0, FLAGS);
  KEXPECT_EQ(22, result);
  KEXPECT_STREQ("[ NOT_F2 T1(0) T2(0) ]", buf);

  KTEST_BEGIN("basic test");
  result = flag_sprintf(buf, 0xFFF, FLAGS);
  KEXPECT_EQ(33, result);
  KEXPECT_STREQ("[ F1 F2 FFF3 FFFF4 T1(3) T2(31) ]", buf);

  result = flag_sprintf(buf, 0x12, FLAGS);
  KEXPECT_EQ(24, result);
  KEXPECT_STREQ("[ F2 FFFF4 T1(0) T2(0) ]", buf);

  KTEST_BEGIN("field test");
  result = flag_sprintf(buf, 0x3C0, FLAGS);
  KEXPECT_EQ(22, result);
  KEXPECT_STREQ("[ NOT_F2 T1(2) T2(7) ]", buf);
}
