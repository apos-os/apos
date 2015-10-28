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

const char* do_printf(const char* fmt, ...) {
  static char buffer[500];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buffer, fmt, args);
  va_end(args);
  return buffer;
}

static void kprintf_testA(void) {
  // First test that ksprintf() itself works.
  KTEST_BEGIN("ksprintf(): basic tests");
  char buf[300];
  ksprintf(buf, "%d %x %s", -5, 0x123, "abc");
  KEXPECT_STREQ("-5 123 abc", buf);

  // The rest of the tests use do_printf() as a helper.
  KTEST_BEGIN("ksprintf()");

  KEXPECT_STREQ("", do_printf(""));

  KEXPECT_STREQ("abc", do_printf("abc"));

  KEXPECT_STREQ("a", do_printf("a"));

  KEXPECT_STREQ("a%b", do_printf("a%%b"));

  KEXPECT_STREQ("arg1", do_printf("%s", "arg1"));

  KEXPECT_STREQ("prefixarg1", do_printf("prefix%s", "arg1"));

  KEXPECT_STREQ("arg1arg2arg3", do_printf("%s%s%s", "arg1", "arg2", "arg3"));

  KEXPECT_STREQ("arg1 -- arg2 -- arg3", do_printf("%s -- %s -- %s", "arg1",
                                                  "arg2", "arg3"));

  // Test %d and %i.
  KEXPECT_STREQ("10", do_printf("%d", 10));

  KEXPECT_STREQ("99 123 -459", do_printf("%d %i %d", 99, 123, -459));

  // Test %u.
  KEXPECT_STREQ("4294967295  0  5", do_printf("%u  %u  %u", 0xFFFFFFFF, 0, 5));

  // Test %x.
  KEXPECT_STREQ("10", do_printf("%x", 0x10));

  KEXPECT_STREQ("deadbeef", do_printf("%x", 0xDEADBEEF));

  // Test %X.
  KEXPECT_STREQ("10", do_printf("%X", 0x10));

  KEXPECT_STREQ("DEADBEEF baadf00d",
                do_printf("%X %x", 0xDEADBEEF, 0xBAADF00D));

  // Test trailing %.
  KEXPECT_STREQ("abc", do_printf("abc%"));

  // Put it all together.
  ksprintf(buf, "string:%s, int:%i, int:%i, hex:%X, percent:%%",
           "abc", 10, -10, 0xbeef);
  KEXPECT_STREQ("string:abc, int:10, int:-10, hex:BEEF, percent:%", buf);
}

static void kprintf_testB(void) {
  // Test field width.
  KTEST_BEGIN("ksprintf(): field width");
  KEXPECT_STREQ("5", do_printf("%1d", 5));
  KEXPECT_STREQ(" 5", do_printf("%2d", 5));
  KEXPECT_STREQ("         5", do_printf("%10d", 5));
  KEXPECT_STREQ("123", do_printf("%2d", 123));
  KEXPECT_STREQ("-123", do_printf("%2d", -123));
  KEXPECT_STREQ("-1", do_printf("%2d", -1));
  KEXPECT_STREQ(" -1", do_printf("%3d", -1));
  KEXPECT_STREQ("  a", do_printf("%3s", "a"));
  KEXPECT_STREQ("  c", do_printf("%3x", 12));
  KEXPECT_STREQ("  C", do_printf("%3X", 12));
  KEXPECT_STREQ("  beef", do_printf("%6x", 0xbeef));
  KEXPECT_STREQ("  BEEF", do_printf("%6X", 0xbeef));
  KEXPECT_STREQ("  a   12   beef", do_printf("%3s %4d %6x", "a", 12, 0xbeef));
  KEXPECT_STREQ("555", do_printf("%1d%1d%1d", 5, 5, 5));
  KEXPECT_STREQ("-5-5-5", do_printf("%1d%1d%1d", -5, -5, -5));
  KEXPECT_STREQ("   -5abc  -5def -5hij",
                do_printf("%5dabc%4ddef%3dhij", -5, -5, -5));

  // Test the '0' flag.
  KTEST_BEGIN("ksprintf(): '0' flag");
  KEXPECT_STREQ("5", do_printf("%0d", 5));
  KEXPECT_STREQ("-5", do_printf("%0d", -5));
  KEXPECT_STREQ("5", do_printf("%01d", 5));
  KEXPECT_STREQ("005", do_printf("%03d", 5));
  KEXPECT_STREQ("-05", do_printf("%03d", -5));
  KEXPECT_STREQ("-1234", do_printf("%03d", -1234));
  KEXPECT_STREQ("-00123", do_printf("%06d", -123));
  KEXPECT_STREQ("-01234", do_printf("%06d", -1234));
  KEXPECT_STREQ("005", do_printf("%03i", 5));
  KEXPECT_STREQ("005", do_printf("%03u", 5));
  KEXPECT_STREQ("015", do_printf("%03x", 21));
  KEXPECT_STREQ("015", do_printf("%03X", 21));
  KEXPECT_STREQ("  s", do_printf("%03s", "s"));
  KEXPECT_STREQ(" ab", do_printf("%03s", "ab"));
  KEXPECT_STREQ(" -1", do_printf("%03s", "-1"));
  KEXPECT_STREQ("-0005abc-005def-05hij",
                do_printf("%05dabc%04ddef%03dhij", -5, -5, -5));
}

static void kprintf_testC(void) {
  // Test the ' ' flag.
  KTEST_BEGIN("ksprintf(): ' ' flag");
  KEXPECT_STREQ(" 5", do_printf("% d", 5));
  KEXPECT_STREQ("-5", do_printf("% d", -5));
  KEXPECT_STREQ(" 5", do_printf("% i", 5));
  KEXPECT_STREQ("-5", do_printf("% i", -5));
  KEXPECT_STREQ("c", do_printf("% x", 12));
  KEXPECT_STREQ("C", do_printf("% X", 12));
  KEXPECT_STREQ("12", do_printf("% u", 12));
  KEXPECT_STREQ("x", do_printf("% s", "x"));
  KEXPECT_STREQ(" 0015", do_printf("% 05d", 15));
  KEXPECT_STREQ("-0015", do_printf("% 05d", -15));
  KEXPECT_STREQ(" 0015", do_printf("%0 5d", 15));
  KEXPECT_STREQ("-0015", do_printf("%0 5d", -15));
  KEXPECT_STREQ("-0015 15 15 -15",
                do_printf("%0 5d%0 3d% 3d% 4d", -15, 15, 15, -15));
  KEXPECT_STREQ(" 0", do_printf("% d", 0));
  KEXPECT_STREQ(" 0000", do_printf("% 05d", 0));
  KEXPECT_STREQ(" 0000", do_printf("% 05i", 0));


  // Test the '+' flag.
  KTEST_BEGIN("ksprintf(): '+' flag");
  KEXPECT_STREQ("+5", do_printf("%+d", 5));
  KEXPECT_STREQ("-5", do_printf("%+d", -5));
  KEXPECT_STREQ("+5", do_printf("%+ d", 5));
  KEXPECT_STREQ("-5", do_printf("%+ d", -5));
  KEXPECT_STREQ("+5", do_printf("% +d", 5));
  KEXPECT_STREQ(" +5", do_printf("%+ 3d", 5));
  KEXPECT_STREQ(" +5", do_printf("% +3d", 5));
  KEXPECT_STREQ("+5", do_printf("%+i", 5));
  KEXPECT_STREQ("-5", do_printf("%+i", -5));
  KEXPECT_STREQ("c", do_printf("%+x", 12));
  KEXPECT_STREQ("C", do_printf("%+X", 12));
  KEXPECT_STREQ("12", do_printf("%+u", 12));
  KEXPECT_STREQ("x", do_printf("%+s", "x"));
  KEXPECT_STREQ("+0015", do_printf("%+05d", 15));
  KEXPECT_STREQ("-0015", do_printf("%+05d", -15));
  KEXPECT_STREQ("+0015", do_printf("%0+5d", 15));
  KEXPECT_STREQ("-0015", do_printf("%0+5d", -15));
  KEXPECT_STREQ("-0015+15+15 -15",
                do_printf("%0+5d%0+3d%+3d%+4d", -15, 15, 15, -15));
  KEXPECT_STREQ("+0", do_printf("%+d", 0));
  KEXPECT_STREQ("+0000", do_printf("%+05d", 0));
  KEXPECT_STREQ("+0000", do_printf("%+05i", 0));
}

static void kprintf_testD(void) {
  // Test the '-' flag.
  KTEST_BEGIN("ksprintf(): '-' flag");
  KEXPECT_STREQ("5", do_printf("%-d", 5));
  KEXPECT_STREQ("-5", do_printf("%-d", -5));
  KEXPECT_STREQ("12   ", do_printf("%-5d", 12));
  KEXPECT_STREQ("-12  ", do_printf("%-5d", -12));
  KEXPECT_STREQ("-12  ", do_printf("%-5i", -12));
  KEXPECT_STREQ("12   ", do_printf("%-5u", 12));
  KEXPECT_STREQ("12   ", do_printf("%-05u", 12));
  KEXPECT_STREQ("12   ", do_printf("%0-5u", 12));
  KEXPECT_STREQ("24   ", do_printf("%-05x", 36));
  KEXPECT_STREQ("24   ", do_printf("%-05X", 36));
  KEXPECT_STREQ("+36  ", do_printf("%-+5d", 36));
  KEXPECT_STREQ("+36", do_printf("%-+2d", 36));
  KEXPECT_STREQ("+36", do_printf("%-+3d", 36));
  KEXPECT_STREQ(" 36  ", do_printf("%- 5d", 36));
  KEXPECT_STREQ("abc  ", do_printf("%-5s", "abc"));
  KEXPECT_STREQ("abc", do_printf("%-2s", "abc"));

  KTEST_BEGIN("ksprintf(): '%x'/'%X' with zero");
  KEXPECT_STREQ("0", do_printf("%x", 0));
  KEXPECT_STREQ("0", do_printf("%X", 0));
  KEXPECT_STREQ("  0", do_printf("%3x", 0));
  KEXPECT_STREQ("  0", do_printf("%3X", 0));
  KEXPECT_STREQ("0  ", do_printf("%-3x", 0));
  KEXPECT_STREQ("0  ", do_printf("%-3X", 0));
}

static void kprintf_testE(void) {
  // Test the '#' flag.
  KTEST_BEGIN("ksprintf(): '#' flag");
  KEXPECT_STREQ("0", do_printf("%#d", 0));
  KEXPECT_STREQ("123", do_printf("%#d", 123));
  KEXPECT_STREQ("-123", do_printf("%#d", -123));
  KEXPECT_STREQ("123", do_printf("%#i", 123));
  KEXPECT_STREQ("abcd", do_printf("%#s", "abcd"));
  KEXPECT_STREQ("0", do_printf("%#x", 0));
  KEXPECT_STREQ("0x7b", do_printf("%#x", 123));
  KEXPECT_STREQ("0", do_printf("%#X", 0));
  KEXPECT_STREQ("0X7B", do_printf("%#X", 123));
  KEXPECT_STREQ("    0", do_printf("%#5x", 0));
  KEXPECT_STREQ(" 0x7b", do_printf("%#5x", 123));
  KEXPECT_STREQ("    0", do_printf("%#5X", 0));
  KEXPECT_STREQ(" 0X7B", do_printf("%#5X", 123));

  // Test '%p'.
  KTEST_BEGIN("ksprintf(): '%p'");
  KEXPECT_STREQ("0x123", do_printf("%p", (void*)0x123));
  KEXPECT_STREQ("0x123abcd", do_printf("%p", (void*)0x123ABCD));
  KEXPECT_STREQ("0x123", do_printf("%p", (int*)0x123));
  KEXPECT_STREQ("0x123", do_printf("%4p", (int*)0x123));
  KEXPECT_STREQ("   0x123", do_printf("%8p", (int*)0x123));
  KEXPECT_STREQ("0x000123", do_printf("%08p", (int*)0x123));
  KEXPECT_STREQ("0x123   ", do_printf("%-8p", (int*)0x123));

  // Test '%c'.
  KTEST_BEGIN("ksprintf(): '%c'");
  KEXPECT_STREQ("x", do_printf("%c", 'x'));
  KEXPECT_STREQ("  x", do_printf("%3c", 'x'));
  KEXPECT_STREQ("x  ", do_printf("%-3c", 'x'));
}

static void kprintf_testF(void) {
  KTEST_BEGIN("ksprintf(): 'hh' modifier");
  KEXPECT_STREQ("23", do_printf("%hhi", (char)23));
  KEXPECT_STREQ("-10", do_printf("%hhi", (char)-10));
  KEXPECT_STREQ("-26", do_printf("%hhi", (char)230));
  KEXPECT_STREQ("230", do_printf("%hhu", (unsigned char)230));
  KEXPECT_STREQ("44", do_printf("%hhu", (unsigned char)300));

  KTEST_BEGIN("ksprintf(): 'h' modifier");
  KEXPECT_STREQ("16000", do_printf("%hi", (short)16000));
  KEXPECT_STREQ("-16000", do_printf("%hi", (short)-16000));
  KEXPECT_STREQ("-13536", do_printf("%hi", (short)52000));
  KEXPECT_STREQ("52000", do_printf("%hu", (unsigned short)52000));
  KEXPECT_STREQ("4464", do_printf("%hu", (unsigned short)70000));

  KTEST_BEGIN("ksprintf(): 'l' modifier");
  KEXPECT_STREQ("2147483600", do_printf("%li", 2147483600L));
  KEXPECT_STREQ("2147483600", do_printf("%lu", 2147483600L));
  KEXPECT_STREQ("-2147483600", do_printf("%li", -2147483600L));
  KEXPECT_STREQ("2147483600", do_printf("%lu", 2147483600UL));
  KEXPECT_STREQ("3000000000", do_printf("%lu", 3000000000UL));
  KEXPECT_STREQ("-00123", do_printf("%06ld", -123L));

  if (sizeof(long) == 4) {
    KTEST_BEGIN("ksprintf(): 'l' modifier (32-bit)");
    KEXPECT_STREQ("-1294967296", do_printf("%li", (long)3000000000L));
    KEXPECT_STREQ("705032704", do_printf("%lu", (unsigned long)5000000000));
  }

  if (sizeof(long) == 8) {
    KTEST_BEGIN("ksprintf(): 'l' modifier (64-bit)");
    KEXPECT_STREQ("18446744069720004216",
                  do_printf("%lu", 0xFFFFFFFF12345678L));
    KEXPECT_STREQ("3000000000", do_printf("%li", 3000000000L));
    KEXPECT_STREQ("-1", do_printf("%li", 0xFFFFFFFFFFFFFFFFL));
    KEXPECT_STREQ("3000000000", do_printf("%lu", (long)3000000000UL));
    KEXPECT_STREQ("18446744073709551615",
                  do_printf("%lu", 0xFFFFFFFFFFFFFFFFUL));
    KEXPECT_STREQ("-9223372036854775808", do_printf("%ld", 0x8000000000000000));
    KEXPECT_STREQ("0", do_printf("%d", 0x8000000000000000));
  }

  // TODO(aoates): implement 'll' support.
#if 0
  KTEST_BEGIN("ksprintf(): 'll' modifier");
  KEXPECT_STREQ("9223372036854775807", do_printf("%lli", 9223372036854775807));
  KEXPECT_STREQ("9223372036854775807", do_printf("%llu", 9223372036854775807));
  KEXPECT_STREQ("18446744073709551615",
                do_printf("%llu", 18446744073709551615U));
  KEXPECT_STREQ("-9223372036854775807",
                do_printf("%lli", -9223372036854775807));
  KEXPECT_STREQ("9223372036854775807",
                do_printf("%lli", (long long)9223372036854775807));
  KEXPECT_STREQ("-00123", do_printf("%06lld", -123));
#endif

  KTEST_BEGIN("ksprintf(): 'z' modifier");
  KEXPECT_STREQ("55", do_printf("%zi", (addr_t)55));
  KEXPECT_STREQ("-55", do_printf("%zi", (addr_t)-55));
  KEXPECT_STREQ("55", do_printf("%zu", (addr_t)55));

  KTEST_BEGIN("ksprintf(): bad length modifiers");
  KEXPECT_STREQ("u", do_printf("%qu", 5));
  KEXPECT_STREQ("h", do_printf("%h", 5));
  KEXPECT_STREQ("l", do_printf("%l", 5));
  KEXPECT_STREQ("", do_printf("%hhh", 5));
  KEXPECT_STREQ("u", do_printf("%lhu", 5));
  KEXPECT_STREQ("u", do_printf("%hlu", 5));
}

void kprintf_test(void) {
  KTEST_SUITE_BEGIN("kprintf");
  kprintf_testA();
  kprintf_testB();
  kprintf_testC();
  kprintf_testD();
  kprintf_testE();
  kprintf_testF();
}
