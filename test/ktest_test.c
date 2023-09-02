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

static void multiline_test(void) {
  KTEST_BEGIN("KEXPECT_MULTILINE_STREQ(): SHOULD PASS");
  KEXPECT_MULTILINE_STREQ("a", "a");
  KEXPECT_MULTILINE_STREQ("\na", "\na");
  KEXPECT_MULTILINE_STREQ("a\n", "a\n");
  KEXPECT_MULTILINE_STREQ("a\nbcd\neee", "a\nbcd\neee");
  KASSERT(ktest_current_test_failures() == 0);

  KTEST_BEGIN("KEXPECT_MULTILINE_STREQ(): SHOULD FAIL");
  KEXPECT_MULTILINE_STREQ("a", "b");
  KEXPECT_MULTILINE_STREQ("", "a");
  KEXPECT_MULTILINE_STREQ("\n", "\n\n");
  KEXPECT_MULTILINE_STREQ("\n", "a");
  KEXPECT_MULTILINE_STREQ("\n", "");
  KEXPECT_MULTILINE_STREQ("a\nA", "a\nB");
  KEXPECT_MULTILINE_STREQ("a\nA\n", "a\nB\n");
  KEXPECT_MULTILINE_STREQ("a\nb\nc\nd\ne", "a\nB\nC\nD\nE");
  KEXPECT_MULTILINE_STREQ("a\nb\nc\nd\ne", "a\nB\nc\nd\nE");
  KEXPECT_MULTILINE_STREQ("ab\ncd\ne", "ab\ncd\nef");
  KEXPECT_MULTILINE_STREQ("ab\ncd\ne", "ab\ncd\ne\n");
  KEXPECT_MULTILINE_STREQ("ab\ncd\ne\n", "ab\ncd\ne");
  KEXPECT_MULTILINE_STREQ("ab\ncd\ne\n", "ab\ncd\nE\n");
  KASSERT(ktest_current_test_failures() == 13);
}

static void int_conv_test(void) {
  KTEST_BEGIN("KEXPECT_EQ(): int conversion SHOULD PASS");
  KEXPECT_EQ(0, 0);
  KEXPECT_EQ((uint8_t)0, 0);
  KEXPECT_EQ((uint8_t)0, (uint32_t)0);
  KEXPECT_EQ(0, 0l);
  KEXPECT_EQ(0, 0ll);
  KEXPECT_EQ(0l, 0);
  KEXPECT_EQ(0ll, 0);
  // Should fail to compile:
  // KEXPECT_NE((uint32_t)0x2, (uint64_t)0x100000002);
  KEXPECT_NE((uint64_t)0x100000002, (uint32_t)0x2);
  KEXPECT_EQ(0xffffffffffffffff,
             0xffffffffffffffff);
  KEXPECT_EQ(0xffffffffffffffff, -1);

  uint32_t x32 = 2;
  uint64_t x64 = 0x100000002;
  // TODO(aoates): fix this one:
  // KEXPECT_NE(x32, x64);
  KEXPECT_NE(x64, x32);
  KASSERT(ktest_current_test_failures() == 0);

  KTEST_BEGIN("KEXPECT_EQ(): int conversion SHOULD FAIL x7");
  KEXPECT_EQ(0, 1);
  KEXPECT_EQ((uint32_t)0, (uint64_t)1);
  // Should fail to compile:
  // KEXPECT_EQ((uint32_t)0x2, (uint64_t)0x100000002);
  KEXPECT_EQ((uint64_t)0x100000002, (uint32_t)0x2);
  // TODO(aoates): fix this one:
  // KEXPECT_EQ(x32, x64);
  KEXPECT_EQ(x64, x32);
  KEXPECT_NE(0xffffffffffffffff,
             0xffffffffffffffff);
  KEXPECT_EQ(0xffffffffffffffff,
             0x7fffffffffffffff);
  KEXPECT_NE(0xffffffffffffffff, -1);
  KASSERT(ktest_current_test_failures() == 7);
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
  KASSERT(ktest_current_test_failures() == 1);

  KTEST_BEGIN("KEXPECT_EQ (hex) [PFFF]");
  KEXPECT_EQ(0xdeadbeef, 0xdeadbeef);
  KEXPECT_EQ(0xdeadbeef, 0xbaadf00d);
  KEXPECT_EQ(0xdeadbeef, 1);
  KEXPECT_EQ(1, 0xdeadbeef);
  KASSERT(ktest_current_test_failures() == 3);

  KTEST_BEGIN("KEXPECT_STREQ [PF]");
  KEXPECT_STREQ("abc", "abc");
  KEXPECT_STREQ("abc", "def");
  KASSERT(ktest_current_test_failures() == 1);

  KTEST_BEGIN("KEXPECT_NE [PF]");
  KEXPECT_NE(1, 2);
  KEXPECT_NE(1, 1);
  KASSERT(ktest_current_test_failures() == 1);

  KTEST_BEGIN("KEXPECT_STRNE [PF]");
  KEXPECT_STRNE("abc", "def");
  KEXPECT_STRNE("abc", "abc");
  KASSERT(ktest_current_test_failures() == 1);

  KTEST_BEGIN("KEXPECT_LT [PPFF]");
  KEXPECT_LT(1, 2);
  KEXPECT_LT(-1, 0);
  KEXPECT_LT(1, 1);
  KEXPECT_LT(2, 1);
  KASSERT(ktest_current_test_failures() == 2);

  KTEST_BEGIN("KEXPECT_LE [PPPF]");
  KEXPECT_LE(1, 2);
  KEXPECT_LE(-1, 0);
  KEXPECT_LE(1, 1);
  KEXPECT_LE(2, 1);
  KASSERT(ktest_current_test_failures() == 1);

  KTEST_BEGIN("KEXPECT_GT [PPFF]");
  KEXPECT_GT(3, 2);
  KEXPECT_GT(0, -1);
  KEXPECT_GT(1, 1);
  KEXPECT_GT(0, 1);
  KASSERT(ktest_current_test_failures() == 2);

  KTEST_BEGIN("KEXPECT_GE [PPPF]");
  KEXPECT_GE(3, 2);
  KEXPECT_GE(0, -1);
  KEXPECT_GE(1, 1);
  KEXPECT_GE(0, 1);
  KASSERT(ktest_current_test_failures() == 1);

  // Verify that the EXPECT macros don't evaluate their args twice (and
  // therefore don't screw up any side effects).
  KTEST_BEGIN("KEXPEXT_EQ no side effects (SHOULD PASS)");
  int x = 0;
  KEXPECT_EQ(1, ++x);
  KEXPECT_EQ(1, x);
  KASSERT(ktest_current_test_failures() == 0);

  KTEST_BEGIN("KEXPEXT_STREQ no side effects (SHOULD PASS)");
  char buf[2];
  buf[0] = 'a';
  buf[1] = '\0';
  KEXPECT_STREQ("b", inc_char(buf));
  KEXPECT_STREQ("b", buf);
  KASSERT(ktest_current_test_failures() == 0);

  KTEST_BEGIN("KEXPECT_NULL(): should pass");
  void* ptr = NULL;
  const void* cptr = NULL;
  KEXPECT_NULL(ptr);
  KEXPECT_NULL(cptr);
  KEXPECT_NULL(NULL);
  KEXPECT_NULL(0x0);
  KEXPECT_NULL(0);
  ptr = (void*)0x1234;
  cptr = (const void*)0x1234;
  KEXPECT_NOT_NULL(ptr);
  KEXPECT_NOT_NULL(cptr);
  // KEXPECT_NOT_NULL(1);
  KASSERT(ktest_current_test_failures() == 0);

  KTEST_BEGIN("KEXPECT_NULL(): should fail x7");
  ptr = NULL;
  cptr = NULL;
  KEXPECT_NOT_NULL(ptr);
  KEXPECT_NOT_NULL(cptr);
  KEXPECT_NOT_NULL(NULL);
  KEXPECT_NOT_NULL(0x0);
  KEXPECT_NOT_NULL(0);
  ptr = (void*)0x1234;
  cptr = (const void*)0x1234;
  KEXPECT_NULL(ptr);
  KEXPECT_NULL(cptr);
  // KEXPECT_NULL(1);
  KASSERT(ktest_current_test_failures() == 7);

  multiline_test();
  int_conv_test();
}

void kassert_test(void) {
  KTEST_SUITE_BEGIN("kassert");

  KTEST_BEGIN("KASSERT no side effects");
  int x = 0;
  KASSERT(++x);
  KEXPECT_EQ(1, x);
}
