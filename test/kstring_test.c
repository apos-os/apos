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

#include <limits.h>

#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"

static void kstring_testA(void) {
  KTEST_BEGIN("kstrlen()");
  KEXPECT_EQ(0, kstrlen(""));
  KEXPECT_EQ(1, kstrlen("a"));
  KEXPECT_EQ(6, kstrlen("abcdef"));
  KEXPECT_EQ(3, kstrlen("abc\0def"));

  KTEST_BEGIN("kstrnlen()");
  KEXPECT_EQ(0, kstrnlen("", 5));
  KEXPECT_EQ(-1, kstrnlen("", 0));
  KEXPECT_EQ(3, kstrnlen("abc", 5));
  KEXPECT_EQ(3, kstrnlen("abc", 4));
  KEXPECT_EQ(-1, kstrnlen("abc", 3));

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
}

static void kstring_testB(char* buf) {
  KTEST_BEGIN("kstrcat()");
  buf[0] = '\0';
  kstrcat(buf, "a");
  KEXPECT_STREQ("a", buf);
  kstrcat(buf, "b");
  KEXPECT_STREQ("ab", buf);
  kstrcat(buf, "ABCDEFG");
  KEXPECT_STREQ("abABCDEFG", buf);

  KTEST_BEGIN("utoa()");
  KEXPECT_STREQ("0", utoa(0));
  KEXPECT_STREQ("0", utoa(00));
  KEXPECT_STREQ("10", utoa(10));
  KEXPECT_STREQ("100", utoa(100));
  KEXPECT_STREQ("123", utoa(123));
  KEXPECT_STREQ("1234567890", utoa(1234567890));
  KEXPECT_STREQ("4294967295", utoa(0xFFFFFFFF));
  if (sizeof(unsigned long) == 8) {
    // The explicit casts here and below are to keep gcc happy in 32-bit mode
    // with -Woverflow (even those these lines won't be executed).
    KEXPECT_STREQ("18446744073709551615",
                  utoa((unsigned long)0xFFFFFFFFFFFFFFFF));
  }
  _Static_assert(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8,
                 "Unsupported sizeof(unsigned long)");

  KTEST_BEGIN("utoa_hex()");
  KEXPECT_STREQ("0", utoa_hex(0));
  KEXPECT_STREQ("0", utoa_hex(00));
  KEXPECT_STREQ("10", utoa_hex(0x10));
  KEXPECT_STREQ("DEADBEEF", utoa_hex(0xDEADBEEF));
  KEXPECT_STREQ("12345", utoa_hex(0x12345));
  KEXPECT_STREQ("67890", utoa_hex(0x67890));
  KEXPECT_STREQ("ABCDEF0", utoa_hex(0xABCDEF0));
  KEXPECT_STREQ("FFFFFFFF", utoa_hex(0xFFFFFFFF));
  if (sizeof(unsigned long) == 8) {
    KEXPECT_STREQ("FFFFFFFFFFFFFFFF",
                  utoa_hex((unsigned long)0xFFFFFFFFFFFFFFFF));
  }
  _Static_assert(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8,
                 "Unsupported sizeof(unsigned long)");

  KTEST_BEGIN("utoa_hex_lower()");
  KEXPECT_STREQ("0", utoa_hex_lower(0));
  KEXPECT_STREQ("0", utoa_hex_lower(00));
  KEXPECT_STREQ("10", utoa_hex_lower(0x10));
  KEXPECT_STREQ("deadbeef", utoa_hex_lower(0xDEADBEEF));
  KEXPECT_STREQ("12345", utoa_hex_lower(0x12345));
  KEXPECT_STREQ("67890", utoa_hex_lower(0x67890));
  KEXPECT_STREQ("abcdef0", utoa_hex_lower(0xABCDEF0));
  if (sizeof(unsigned long) == 8) {
    KEXPECT_STREQ("ffffffffffffffff",
                  utoa_hex_lower((unsigned long)0xFFFFFFFFFFFFFFFF));
  }

  KTEST_BEGIN("itoa()");
  KEXPECT_STREQ("0", itoa(0));
  KEXPECT_STREQ("0", itoa(-0));
  KEXPECT_STREQ("10", itoa(10));
  KEXPECT_STREQ("-10", itoa(-10));
  KEXPECT_STREQ("100", itoa(100));
  KEXPECT_STREQ("123", itoa(123));
  KEXPECT_STREQ("1234567890", itoa(1234567890));
  KEXPECT_STREQ("-1234567890", itoa(-1234567890));
  KEXPECT_STREQ("2147483647", itoa(0x7FFFFFFF));
  if (sizeof(long) == 4) {
    KEXPECT_STREQ("-2147483648", itoa(0x80000000));
    KEXPECT_STREQ("-2147483647", itoa(0x80000001));
  } else if (sizeof(long) == 8) {
    KEXPECT_STREQ("2147483648", itoa(0x80000000));
    KEXPECT_STREQ("2147483649", itoa(0x80000001));
    KEXPECT_STREQ("-9223372036854775808", itoa((long)0x8000000000000000));
    KEXPECT_STREQ("-9223372036854775807", itoa((long)0x8000000000000001));
  }
  _Static_assert(sizeof(long) == 4 || sizeof(long) == 8,
                 "Unsupported sizeof(long)");

  KTEST_BEGIN("itoa_hex()");
  KEXPECT_STREQ("0", itoa_hex(0));
  KEXPECT_STREQ("0", itoa_hex(-0));
  KEXPECT_STREQ("10", itoa_hex(0x10));
  KEXPECT_STREQ("DEAD", itoa_hex(0xDEAD));
  KEXPECT_STREQ("12345", itoa_hex(0x12345));
  KEXPECT_STREQ("67890", itoa_hex(0x67890));
  KEXPECT_STREQ("ABCDEF0", itoa_hex(0xABCDEF0));
  KEXPECT_STREQ("-ABCDEF0", itoa_hex(-0xABCDEF0));
  KEXPECT_STREQ("7FFFFFFF", itoa_hex(0x7FFFFFFF));
  if (sizeof(long) == 4) {
    KEXPECT_STREQ("-80000000", itoa_hex(0x80000000));
    KEXPECT_STREQ("-7FFFFFFF", itoa_hex(0x80000001));
  } else if (sizeof(long) == 8) {
    KEXPECT_STREQ("80000000", itoa_hex(0x80000000));
    KEXPECT_STREQ("80000001", itoa_hex(0x80000001));
    KEXPECT_STREQ("-8000000000000000", itoa_hex((long)0x8000000000000000));
    KEXPECT_STREQ("-7FFFFFFFFFFFFFFF", itoa_hex((long)0x8000000000000001));
  }
  _Static_assert(sizeof(long) == 4 || sizeof(long) == 8,
                 "Unsupported sizeof(long)");
}

static void kstring_testC(void) {
  KTEST_BEGIN("atoi()");
  KEXPECT_EQ(0, atoi("0"));
  KEXPECT_EQ(10, atoi("10"));
  KEXPECT_EQ(-10, atoi("-10"));
  KEXPECT_EQ(12345, atoi("12345"));
  KEXPECT_EQ(7890, atoi("7890"));
  KEXPECT_EQ(-7890, atoi("-7890"));
  KEXPECT_EQ(-7890, atoi("-7890abc"));
  KEXPECT_EQ(0x7FFFFFFF, atoi("2147483647"));
  KEXPECT_EQ(-0x80000000, atoi("-2147483648"));
  // TODO(aoates): add 64-bit tests.

  KTEST_BEGIN("atoi() -- hex");
  KEXPECT_EQ(0x10, atoi("0x10"));
  KEXPECT_EQ(-0x10, atoi("-0x10"));
  KEXPECT_EQ(0x12345, atoi("0x12345"));
  KEXPECT_EQ(-0xABCDEF, atoi("-0xABCDEF"));
  KEXPECT_EQ(-0xABCDEF, atoi("-0XaBcDeF"));
  KEXPECT_EQ(0xABCDEF1, atoi("0xABCDEF1Q"));
  KEXPECT_EQ(0x7FFFFFFF, atoi("0x7FFFFFFF"));
  KEXPECT_EQ(-0x80000000, atoi("-0x80000000"));

  KTEST_BEGIN("atou()");
  KEXPECT_EQ(0, atou("0"));
  KEXPECT_EQ(10, atou("10"));
  KEXPECT_EQ(12345, atou("12345"));
  KEXPECT_EQ(7890, atou("7890"));
  KEXPECT_EQ(1234567890, atou("1234567890"));
  KEXPECT_EQ(7890, atou("7890abc"));
  KEXPECT_EQ(0xFFFFFFFF, atou("4294967295"));

  KTEST_BEGIN("atou() -- hex");
  KEXPECT_EQ(0x10, atou("0x10"));
  KEXPECT_EQ(0x12345, atou("0x12345"));
  KEXPECT_EQ(0xABCDEF, atou("0xABCDEF"));
  KEXPECT_EQ(0xABCDEF, atou("0XaBcDeF"));
  KEXPECT_EQ(0xABCDEF1, atou("0xABCDEF1Q"));
  KEXPECT_EQ(0xFFFFFFFF, atou("0xFFFFFFFF"));
}

static void kstring_testD(char* buf) {
  KTEST_BEGIN("kstrchr()");
  const char* s = "/abc/def";
  KEXPECT_EQ(s, kstrchr(s, '/'));
  KEXPECT_EQ(s+1, kstrchr(s, 'a'));
  KEXPECT_EQ((const char*)0, kstrchr(s, 'x'));

  KTEST_BEGIN("kstrrchr()");
  KEXPECT_EQ(s+4, kstrrchr(s, '/'));
  KEXPECT_EQ(s+1, kstrrchr(s, 'a'));
  KEXPECT_EQ((const char*)0, kstrrchr(s, 'x'));

  KTEST_BEGIN("kstrchrnul()");
  KEXPECT_EQ(s, kstrchrnul(s, '/'));
  KEXPECT_EQ(s+1, kstrchrnul(s, 'a'));
  KEXPECT_EQ(s+8, kstrchrnul(s, 'x'));

  KTEST_BEGIN("kmemcmp()");
  KEXPECT_EQ(0, kmemcmp("abc", "abc", 3));
  KEXPECT_EQ(0, kmemcmp("abc", "abc", 2));
  KEXPECT_EQ(0, kmemcmp("abD", "abF", 2));
  KEXPECT_LT(kmemcmp("abc", "bbc", 3), 0);
  KEXPECT_GT(kmemcmp("cbc", "bbc", 3), 0);

  KTEST_BEGIN("kstrncpy()");
  kmemset(buf, 'x', 5);
  kstrncpy(buf, "ab", 4);
  KEXPECT_EQ('a', buf[0]);
  KEXPECT_EQ('b', buf[1]);
  KEXPECT_EQ('\0', buf[2]);
  KEXPECT_EQ('x', buf[4]);

  kmemset(buf, 'x', 5);
  kstrncpy(buf, "abcdefgh", 4);
  KEXPECT_EQ('a', buf[0]);
  KEXPECT_EQ('b', buf[1]);
  KEXPECT_EQ('c', buf[2]);
  KEXPECT_EQ('d', buf[3]);
  KEXPECT_EQ('x', buf[4]);
}

static void kstring_testE(void) {
  KTEST_BEGIN("kisdigit()");
  KEXPECT_EQ(0, kisdigit('a'));
  KEXPECT_EQ(0, kisdigit('Q'));
  KEXPECT_EQ(0, kisdigit('Z'));
  KEXPECT_EQ(0, kisdigit('_'));
  KEXPECT_EQ(0, kisdigit(':'));
  KEXPECT_EQ(0, kisdigit('\0'));
  KEXPECT_EQ(0, kisdigit('\x03'));
  KEXPECT_EQ(1, kisdigit('0'));
  KEXPECT_EQ(1, kisdigit('1'));
  KEXPECT_EQ(1, kisdigit('2'));
  KEXPECT_EQ(1, kisdigit('3'));
  KEXPECT_EQ(1, kisdigit('4'));
  KEXPECT_EQ(1, kisdigit('5'));
  KEXPECT_EQ(1, kisdigit('6'));
  KEXPECT_EQ(1, kisdigit('7'));
  KEXPECT_EQ(1, kisdigit('8'));
  KEXPECT_EQ(1, kisdigit('9'));
  KEXPECT_EQ(0, kisdigit('x'));
  KEXPECT_EQ(0, kisdigit('X'));

  KTEST_BEGIN("kisalpha()");
  KEXPECT_EQ(1, kisalpha('a'));
  KEXPECT_EQ(1, kisalpha('z'));
  KEXPECT_EQ(1, kisalpha('A'));
  KEXPECT_EQ(1, kisalpha('Z'));
  KEXPECT_EQ(1, kisalpha('Q'));
  KEXPECT_EQ(1, kisalpha('b'));
  KEXPECT_EQ(1, kisalpha('x'));
  KEXPECT_EQ(1, kisalpha('X'));
  KEXPECT_EQ(0, kisalpha('_'));
  KEXPECT_EQ(0, kisalpha('*'));
  KEXPECT_EQ(0, kisalpha(':'));
  KEXPECT_EQ(0, kisalpha('\0'));
  KEXPECT_EQ(0, kisalpha('\x03'));
  KEXPECT_EQ(0, kisalpha('0'));
  KEXPECT_EQ(0, kisalpha('5'));
  KEXPECT_EQ(0, kisalpha('9'));

  KTEST_BEGIN("kisalnum()");
  KEXPECT_EQ(1, kisalnum('a'));
  KEXPECT_EQ(1, kisalnum('z'));
  KEXPECT_EQ(1, kisalnum('A'));
  KEXPECT_EQ(1, kisalnum('Z'));
  KEXPECT_EQ(1, kisalnum('x'));
  KEXPECT_EQ(1, kisalnum('X'));
  KEXPECT_EQ(0, kisalnum('_'));
  KEXPECT_EQ(0, kisalnum('*'));
  KEXPECT_EQ(0, kisalnum(':'));
  KEXPECT_EQ(0, kisalnum('\0'));
  KEXPECT_EQ(0, kisalnum('\x03'));
  KEXPECT_EQ(1, kisalnum('0'));
  KEXPECT_EQ(1, kisalnum('5'));
  KEXPECT_EQ(1, kisalnum('9'));

  KTEST_BEGIN("kisspace()");
  KEXPECT_EQ(1, kisspace(' '));
  KEXPECT_EQ(1, kisspace('\t'));
  KEXPECT_EQ(1, kisspace('\n'));
  KEXPECT_EQ(0, kisspace('@'));
  KEXPECT_EQ(0, kisspace('2'));
  KEXPECT_EQ(0, kisspace('x'));
  KEXPECT_EQ(0, kisspace('\x7f'));
  KEXPECT_EQ(0, kisspace('\x03'));

  KTEST_BEGIN("kisprint()");
  KEXPECT_EQ(1, kisprint(' '));
  KEXPECT_EQ(0, kisprint('\t'));
  KEXPECT_EQ(0, kisprint('\n'));
  KEXPECT_EQ(1, kisprint('@'));
  KEXPECT_EQ(1, kisprint('2'));
  KEXPECT_EQ(1, kisprint('x'));
  KEXPECT_EQ(1, kisprint('~'));
  KEXPECT_EQ(0, kisprint('\x7f'));
  KEXPECT_EQ(0, kisprint('\x03'));
  KEXPECT_EQ(0, kisprint('\x1f'));
}

void kstring_test(void) {
  KTEST_SUITE_BEGIN("kstring");

  char* buf = kmalloc(1024);
  kstring_testA();
  kstring_testB(buf);
  kstring_testC();
  kstring_testD(buf);
  kstring_testE();
  kfree(buf);
}
