// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
//
// Some basic tests to kick the tires on libc (newlib).
#include <limits.h>
#include <stdio.h>

#include "user-tests/ktest.h"

static void printf_tests_d(void) {
  KTEST_BEGIN("sprintf(): %d/%i/%u");
  const int kBufSize = 100;
  char buf[kBufSize];
  KEXPECT_EQ(4, sprintf(buf, "%s", "abcd"));
  KEXPECT_STREQ("abcd", buf);
  memset(buf, 0, kBufSize);

  int ival = 5;
  KEXPECT_EQ(1, sprintf(buf, "%d", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  KEXPECT_EQ(1, sprintf(buf, "%i", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  ival = INT_MAX;
  KEXPECT_EQ(10, sprintf(buf, "%d", ival));
  KEXPECT_STREQ("2147483647", buf);
  memset(buf, 0, kBufSize);

  ival = INT_MIN;
  KEXPECT_EQ(11, sprintf(buf, "%d", ival));
  KEXPECT_STREQ("-2147483648", buf);
  memset(buf, 0, kBufSize);

  unsigned int uval = INT_MAX;
  KEXPECT_EQ(10, sprintf(buf, "%u", uval));
  KEXPECT_STREQ("2147483647", buf);
  memset(buf, 0, kBufSize);

  uval = (unsigned int)INT_MAX + 1;
  KEXPECT_EQ(10, sprintf(buf, "%u", uval));
  KEXPECT_STREQ("2147483648", buf);
  memset(buf, 0, kBufSize);

  uval = UINT_MAX;
  KEXPECT_EQ(10, sprintf(buf, "%u", uval));
  KEXPECT_STREQ("4294967295", buf);
  memset(buf, 0, kBufSize);
}

static void printf_tests_dl(void) {
  KTEST_BEGIN("sprintf(): %ld/%li/%lu");
  const int kBufSize = 100;
  char buf[kBufSize];
  long ival = 5;
  KEXPECT_EQ(1, sprintf(buf, "%ld", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  KEXPECT_EQ(1, sprintf(buf, "%li", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  ival = LONG_MAX;
  if (sizeof(long) == 4) {
    KEXPECT_EQ(10, sprintf(buf, "%ld", ival));
    KEXPECT_STREQ("2147483647", buf);
  } else {
    KEXPECT_EQ(19, sprintf(buf, "%ld", ival));
    KEXPECT_STREQ("9223372036854775807", buf);
  }
  memset(buf, 0, kBufSize);

  ival = LONG_MIN;
  if (sizeof(long) == 4) {
    KEXPECT_EQ(11, sprintf(buf, "%ld", ival));
    KEXPECT_STREQ("-2147483648", buf);
  } else {
    KEXPECT_EQ(20, sprintf(buf, "%ld", ival));
    KEXPECT_STREQ("-9223372036854775808", buf);
  }
  memset(buf, 0, kBufSize);

  unsigned long uval = LONG_MAX;
  if (sizeof(long) == 4) {
    KEXPECT_EQ(10, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("2147483647", buf);
  } else {
    KEXPECT_EQ(19, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("9223372036854775807", buf);
  }
  memset(buf, 0, kBufSize);

  uval = (unsigned long)LONG_MAX + 1;
  if (sizeof(long) == 4) {
    KEXPECT_EQ(10, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("2147483648", buf);
  } else {
    KEXPECT_EQ(19, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("9223372036854775808", buf);
  }
  memset(buf, 0, kBufSize);

  uval = ULONG_MAX;
  if (sizeof(long) == 4) {
    KEXPECT_EQ(10, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("4294967295", buf);
  } else {
    KEXPECT_EQ(20, sprintf(buf, "%lu", uval));
    KEXPECT_STREQ("18446744073709551615", buf);
  }
  memset(buf, 0, kBufSize);
}

static void printf_tests_dll(void) {
  KTEST_BEGIN("sprintf(): %lld/%lli/%llu");
  const int kBufSize = 100;
  char buf[kBufSize];

  long long ival = 5;
  KEXPECT_EQ(1, sprintf(buf, "%lld", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  KEXPECT_EQ(1, sprintf(buf, "%lli", ival));
  KEXPECT_STREQ("5", buf);
  memset(buf, 0, kBufSize);

  ival = LLONG_MAX;
  KEXPECT_EQ(19, sprintf(buf, "%lld", ival));
  KEXPECT_STREQ("9223372036854775807", buf);
  memset(buf, 0, kBufSize);

  ival = LLONG_MIN;
  KEXPECT_EQ(20, sprintf(buf, "%lld", ival));
  KEXPECT_STREQ("-9223372036854775808", buf);
  memset(buf, 0, kBufSize);

  unsigned long long uval = LLONG_MAX;
  KEXPECT_EQ(19, sprintf(buf, "%llu", uval));
  KEXPECT_STREQ("9223372036854775807", buf);
  memset(buf, 0, kBufSize);

  uval = (unsigned long long)LLONG_MAX + 1;
  KEXPECT_EQ(19, sprintf(buf, "%llu", uval));
  KEXPECT_STREQ("9223372036854775808", buf);
  memset(buf, 0, kBufSize);

  uval = ULLONG_MAX;
  KEXPECT_EQ(20, sprintf(buf, "%llu", uval));
  KEXPECT_STREQ("18446744073709551615", buf);
  memset(buf, 0, kBufSize);
}

static void printf_tests_double(void) {
  KTEST_BEGIN("sprintf(): float/double/long double");
  const int kBufSize = 100;
  char buf[kBufSize];

  float fval = 1.23;
  KEXPECT_EQ(12, sprintf(buf, "%f %s", fval, "abc"));
  KEXPECT_STREQ("1.230000 abc", buf);
  memset(buf, 0, kBufSize);

  double dval = 1.23;
  KEXPECT_EQ(12, sprintf(buf, "%f %s", dval, "abc"));
  KEXPECT_STREQ("1.230000 abc", buf);
  memset(buf, 0, kBufSize);

  KEXPECT_EQ(12, sprintf(buf, "%lf %s", dval, "abc"));
  KEXPECT_STREQ("1.230000 abc", buf);
  memset(buf, 0, kBufSize);

  long double ldval = 1.23;
  KEXPECT_EQ(12, sprintf(buf, "%Lf %s", ldval, "abc"));
  KEXPECT_STREQ("1.230000 abc", buf);
  memset(buf, 0, kBufSize);
}
static void printf_c99_test(void) {
  KTEST_BEGIN("sprintf(): C99 features");
  const int kBufSize = 100;
  char buf[kBufSize];

  intmax_t max = 100;
  KEXPECT_EQ(3, sprintf(buf, "%jd", max));
  KEXPECT_STREQ("100", buf);

  KEXPECT_EQ(3, sprintf(buf, "%2$i %1$i", 1, 2));
  KEXPECT_STREQ("2 1", buf);
}

static void printf_tests(void) {
  printf_tests_d();
  printf_tests_dl();
  printf_tests_dll();
  printf_tests_double();
  printf_c99_test();
}

void libc_tests(void) {
  KTEST_SUITE_BEGIN("libc tests");
  printf_tests();
}
