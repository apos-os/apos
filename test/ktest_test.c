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

#include "test/ktest.h"

#include "common/kassert.h"
#include "common/kprintf.h"

char* inc_char(char* x) {
  *x = *x + 1;
  return x;
}

void ktest_test(void) {
  KTEST_SUITE_BEGIN("ktest");

  do {
    uint32_t aval = 1;
    uint32_t bval = 1;
    char aval_str[50];
    char bval_str[50];
    if (kstrncmp("1", "0x", 2) == 0 || kstrncmp("1", "0x", 2) == 0) {
      ksprintf(aval_str, "0x%s", kutoa_hex(aval));
      ksprintf(bval_str, "0x%s", kutoa_hex(bval));
    } else {
      kstrcpy(aval_str, kutoa(aval));
      kstrcpy(bval_str, kutoa(bval));
    }
    kexpect(aval == bval, "KEXPECT_EQ", "1", "1", aval_str, bval_str, "'",
            " != ", "test/ktest_test.c", "14");
  } while(0);

  KTEST_BEGIN("KEXPECT_EQ [PF]");
  KEXPECT_EQ(1, 1);
  KEXPECT_EQ(1, 2);

  KTEST_BEGIN("KEXPECT_EQ (hex) [PFFF]");
  KEXPECT_EQ(0xdeadbeef, 0xdeadbeef);
  KEXPECT_EQ(0xdeadbeef, 0xbaadf00d);
  KEXPECT_EQ(0xdeadbeef, 1);
  KEXPECT_EQ(1, 0xdeadbeef);

  KTEST_BEGIN("KEXPECT_STREQ [PF]");
  KEXPECT_STREQ("abc", "abc");
  KEXPECT_STREQ("abc", "def");

  KTEST_BEGIN("KEXPECT_NE [PF]");
  KEXPECT_NE(1, 2);
  KEXPECT_NE(1, 1);

  KTEST_BEGIN("KEXPECT_STRNE [PF]");
  KEXPECT_STRNE("abc", "def");
  KEXPECT_STRNE("abc", "abc");

  KTEST_BEGIN("KEXPECT_LT [PPFF]");
  KEXPECT_LT(1, 2);
  KEXPECT_LT(-1, 0);
  KEXPECT_LT(1, 1);
  KEXPECT_LT(2, 1);

  KTEST_BEGIN("KEXPECT_LE [PPPF]");
  KEXPECT_LE(1, 2);
  KEXPECT_LE(-1, 0);
  KEXPECT_LE(1, 1);
  KEXPECT_LE(2, 1);

  KTEST_BEGIN("KEXPECT_GT [PPFF]");
  KEXPECT_GT(3, 2);
  KEXPECT_GT(0, -1);
  KEXPECT_GT(1, 1);
  KEXPECT_GT(0, 1);

  KTEST_BEGIN("KEXPECT_GE [PPPF]");
  KEXPECT_GE(3, 2);
  KEXPECT_GE(0, -1);
  KEXPECT_GE(1, 1);
  KEXPECT_GE(0, 1);

  // Verify that the EXPECT macros don't evaluate their args twice (and
  // therefore don't screw up any side effects).
  KTEST_BEGIN("KEXPEXT_EQ no side effects (SHOULD PASS)");
  int x = 0;
  KEXPECT_EQ(1, ++x);
  KEXPECT_EQ(1, x);

  KTEST_BEGIN("KEXPEXT_STREQ no side effects (SHOULD PASS)");
  char buf[2];
  buf[0] = 'a';
  buf[1] = '\0';
  KEXPECT_STREQ("b", inc_char(buf));
  KEXPECT_STREQ("b", buf);
}

void kassert_test(void) {
  KTEST_SUITE_BEGIN("kassert");

  KTEST_BEGIN("KASSERT no side effects");
  int x = 0;
  KASSERT(++x);
  KEXPECT_EQ(1, x);
}
