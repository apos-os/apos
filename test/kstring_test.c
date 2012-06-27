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

void kstring_test() {
  KTEST_SUITE_BEGIN("kstring");

  KTEST_BEGIN("kstrlen()");
  KEXPECT_EQ(0, kstrlen(""));
  KEXPECT_EQ(1, kstrlen("a"));
  KEXPECT_EQ(6, kstrlen("abcdef"));
  KEXPECT_EQ(3, kstrlen("abc\0def"));

  KTEST_BEGIN("kstrcmp()");
  KEXPECT_EQ(kstrcmp("abc", "abc"), 0);
  KEXPECT_LT(kstrcmp("abc", "def"), 0);
  KEXPECT_GT(kstrcmp("def", "abc"), 0);
  KEXPECT_LT(kstrcmp("abca", "abcb"), 0);
  KEXPECT_GT(kstrcmp("abcc", "abcb"), 0);
  KEXPECT_LT(kstrcmp("abc", "abcd"), 0);
  KEXPECT_GT(kstrcmp("abcd", "abc"), 0);
  KEXPECT_GT(kstrcmp("abcda", "abcca"), 0);

  KTEST_BEGIN("kstrncmp()");
  // First, the same tests from kstrcmp().
  KEXPECT_EQ(kstrncmp("abc", "abc", 3), 0);
  KEXPECT_LT(kstrncmp("abc", "def", 3), 0);
  KEXPECT_GT(kstrncmp("def", "abc", 3), 0);
  KEXPECT_LT(kstrncmp("abca", "abcb", 4), 0);
  KEXPECT_GT(kstrncmp("abcc", "abcb", 4), 0);
  KEXPECT_LT(kstrncmp("abc", "abcd", 4), 0);
  KEXPECT_GT(kstrncmp("abcd", "abc", 4), 0);
  KEXPECT_GT(kstrncmp("abcda", "abcca", 5), 0);

  // And some new tests.
  KEXPECT_EQ(kstrncmp("abca", "abcb", 3), 0);
  KEXPECT_EQ(kstrncmp("abcc", "abcb", 3), 0);
  KEXPECT_LT(kstrncmp("abca", "abcb", 4), 0);
  KEXPECT_GT(kstrncmp("abcc", "abcb", 4), 0);
  KEXPECT_LT(kstrncmp("abca", "abcb", 10), 0);
  KEXPECT_GT(kstrncmp("abcc", "abcb", 10), 0);
  KEXPECT_LT(kstrncmp("abca", "abcdefghiklmnop", 10), 0);
  KEXPECT_GT(kstrncmp("abcz", "abcdefghiklmnop", 10), 0);

  // TODO(aoates): tests for kmemset, kstrcpy, kstrncpy, kstrcat

  KTEST_BEGIN("utoa()");
  KEXPECT_STREQ("0", utoa(0));
  KEXPECT_STREQ("0", utoa(00));
  KEXPECT_STREQ("10", utoa(10));
  KEXPECT_STREQ("100", utoa(100));
  KEXPECT_STREQ("123", utoa(123));
  KEXPECT_STREQ("1234567890", utoa(1234567890));

  KTEST_BEGIN("utoa_hex()");
  KEXPECT_STREQ("0", utoa_hex(0));
  KEXPECT_STREQ("0", utoa_hex(00));
  KEXPECT_STREQ("10", utoa_hex(0x10));
  KEXPECT_STREQ("DEADBEEF", utoa_hex(0xDEADBEEF));
  KEXPECT_STREQ("12345", utoa_hex(0x12345));
  KEXPECT_STREQ("67890", utoa_hex(0x67890));
  KEXPECT_STREQ("ABCDEF0", utoa_hex(0xABCDEF0));

  KTEST_BEGIN("itoa()");
  KEXPECT_STREQ("0", itoa(0));
  KEXPECT_STREQ("0", itoa(-0));
  KEXPECT_STREQ("10", itoa(10));
  KEXPECT_STREQ("-10", itoa(-10));
  KEXPECT_STREQ("100", itoa(100));
  KEXPECT_STREQ("123", itoa(123));
  KEXPECT_STREQ("1234567890", itoa(1234567890));
  KEXPECT_STREQ("-1234567890", itoa(-1234567890));

  KTEST_BEGIN("itoa_hex()");
  KEXPECT_STREQ("0", itoa_hex(0));
  KEXPECT_STREQ("0", itoa_hex(-0));
  KEXPECT_STREQ("10", itoa_hex(0x10));
  KEXPECT_STREQ("DEAD", itoa_hex(0xDEAD));
  KEXPECT_STREQ("12345", itoa_hex(0x12345));
  KEXPECT_STREQ("67890", itoa_hex(0x67890));
  KEXPECT_STREQ("ABCDEF0", itoa_hex(0xABCDEF0));
  KEXPECT_STREQ("-ABCDEF0", itoa_hex(-0xABCDEF0));
}
