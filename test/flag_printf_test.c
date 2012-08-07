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
  { 0x1, "F1" },
  { 0x2, "F2" },
  { 0x8, "FFF3" },
  { 0x10, "FFFF4" },
  { 0x0, 0x0 },
};

void flag_printf_test() {
  KTEST_SUITE_BEGIN("flag_printf()");

  char buf[100];
  int result;

  KTEST_BEGIN("empty test");
  result = flag_sprintf(buf, 0x0, FLAGS);
  KEXPECT_EQ(3, result);
  KEXPECT_STREQ("[ ]", buf);

  KTEST_BEGIN("basic test");
  result = flag_sprintf(buf, 0xFFF, FLAGS);
  KEXPECT_EQ(20, result);
  KEXPECT_STREQ("[ F1 F2 FFF3 FFFF4 ]", buf);

  result = flag_sprintf(buf, 0x12, FLAGS);
  KEXPECT_EQ(12, result);
  KEXPECT_STREQ("[ F2 FFFF4 ]", buf);
}
