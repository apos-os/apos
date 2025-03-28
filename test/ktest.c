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

#include "common/config.h"
#include "common/errno.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/klog.h"
#include "common/math.h"
#include "dev/timer.h"
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "proc/sleep.h"
#include "test/test_point.h"

// Whether to print all test names (including passing tests)
#define KTEST_PRINT_ALL_TESTS 0

#if ENABLE_TSAN
#undef KTEST_PRINT_ALL_TESTS
#define KTEST_PRINT_ALL_TESTS 1
#endif

// Whether to print all test conditions (including passing ones).
// Implies KTEST_PRINT_ALL_TESTS.
#define KTEST_PRINT_ALL_CONDITIONS 0

#define KTEST_PRINT_ALL_TESTS_VAL \
  (KTEST_PRINT_ALL_TESTS || KTEST_PRINT_ALL_CONDITIONS)

#if ENABLE_TERM_COLOR
# define FAILED "\x1b[1;31m[FAILED]\x1b[0m"
# define PASSED "\x1b[1;32m[PASSED]\x1b[0m"
#else
# define FAILED "[FAILED]"
# define PASSED "[PASSED]"
#endif

// Track statistics about passing and failing tests.
static int num_suites = 0;
static int num_tests = 0;
static int num_suites_passing = 0;
static int num_tests_passing = 0;

// Is the current suite/test passing?
static int current_suite_passing = 0;
static int current_test_passing = 0;
static int current_test_failures = 0;

static apos_ms_t test_start_time;

static const char* current_test_name = 0x0;

// Array of failing test names.  Assumes that test names aren't generated on the
// fly (i.e. the pointers we get to them in KTEST_BEGIN() stay good).
#define FAILING_TEST_NAMES_LEN 100
static const char* failing_test_names[FAILING_TEST_NAMES_LEN];
static int failing_test_names_idx = 0;

// Convert two integer values into strings, appending the errorname if it looks
// like an error code is being returned (one of the operands is zero, and the
// other is between -ERRNO_MIN and -ERRNO_MAX).
// TODO(aoates): make this handle large 64-bit values on 32-bit systems properly
static inline void kexpect_int_to_string(intmax_t aval, intmax_t bval,
                                         char* aval_str, char* bval_str,
                                         size_t bufsize) {
  const int aval_in_range = aval >= -ERRNO_MAX && aval <= -ERRNO_MIN;
  const int bval_in_range = bval >= -ERRNO_MAX && bval <= -ERRNO_MIN;

  kitoa_r(aval, aval_str, bufsize);
  if ((bval_in_range || bval == 0) && aval_in_range) {
    kstrcat(aval_str, " (");
    kstrcat(aval_str, errorname(-aval));
    kstrcat(aval_str, ")");
  }
  kitoa_r(bval, bval_str, bufsize);
  if ((aval_in_range || aval == 0) && bval_in_range) {
    kstrcat(bval_str, " (");
    kstrcat(bval_str, errorname(-bval));
    kstrcat(bval_str, ")");
  }
}

static void finish_test(void) {
  if (current_test_passing) {
    num_tests_passing++;
  } else if (num_tests > 0) {
    if (failing_test_names_idx < FAILING_TEST_NAMES_LEN) {
      failing_test_names[failing_test_names_idx++] = current_test_name;
    }
  }
}

static void finish_suite(void) {
  if (current_suite_passing) {
    num_suites_passing++;
  }
}

void KTEST_SUITE_BEGIN(const char* name) {
  finish_suite();  // Finish the previous suite, if running.
  current_suite_passing = 1;
  num_suites++;
  klogm(KL_TEST, INFO, "\n\nTEST SUITE: ");
  klogm(KL_TEST, INFO, name);
  klogm(KL_TEST, INFO, "\n");
  klogm(KL_TEST, INFO, "#######################################\n");
}

void KTEST_BEGIN(const char* name) {
  finish_test();  // Finish the previous test, if running.
  current_test_name = name;
  current_test_passing = 1;
  current_test_failures = 0;
  num_tests++;
  if (KTEST_PRINT_ALL_TESTS_VAL) {
    klogm(KL_TEST, INFO, "\nTEST: ");
    klogm(KL_TEST, INFO, name);
    klogm(KL_TEST, INFO, "\n");
    klogm(KL_TEST, INFO, "---------------------------------------\n");
  }
}

static void do_failure(void) {
  if (current_test_passing && !KTEST_PRINT_ALL_TESTS_VAL) {
    klogm(KL_TEST, INFO, "\nTEST: ");
    klogm(KL_TEST, INFO, current_test_name);
    klogm(KL_TEST, INFO, "\n");
    klogm(KL_TEST, INFO, "---------------------------------------\n");
  }
  current_test_passing = 0;
  current_suite_passing = 0;
  current_test_failures++;
}

bool kexpect(int cond, const char* name, const char* astr,
             const char* bstr, const char* aval, const char* bval,
             const char* val_surrounders, const char* opstr, const char* file,
             const char* line) {
  if (cond && KTEST_PRINT_ALL_CONDITIONS) {
    klogm(KL_TEST, INFO, PASSED " ");
    klogm(KL_TEST, INFO, name);
    klogm(KL_TEST, INFO, "(");
    klogm(KL_TEST, INFO, astr);
    klogm(KL_TEST, INFO, ", ");
    klogm(KL_TEST, INFO, bstr);
    klogm(KL_TEST, INFO, ")\n");
  } else if (!cond) {
    do_failure();
    klogm(KL_TEST, INFO, FAILED " ");
    klogm(KL_TEST, INFO, name);
    klogm(KL_TEST, INFO, "(");
    klogm(KL_TEST, INFO, astr);
    klogm(KL_TEST, INFO, ", ");
    klogm(KL_TEST, INFO, bstr);
    klogm(KL_TEST, INFO, ") at ");
    klogm(KL_TEST, INFO, file);
    klogm(KL_TEST, INFO, ":");
    klogm(KL_TEST, INFO, line);
    klogm(KL_TEST, INFO, ": ");
    klogm(KL_TEST, INFO, val_surrounders);
    klogm(KL_TEST, INFO, aval);
    klogm(KL_TEST, INFO, val_surrounders);
    klogm(KL_TEST, INFO, opstr);
    klogm(KL_TEST, INFO, val_surrounders);
    klogm(KL_TEST, INFO, bval);
    klogm(KL_TEST, INFO, val_surrounders);
    klogm(KL_TEST, INFO, "\n");
  }
  return cond;
}

bool kexpect_int(const char* name, const char* file, const char* line,
                 const char* astr, const char* bstr, intmax_t aval,
                 intmax_t bval, long result, const char* opstr,
                 kexpect_print_t a_type, kexpect_print_t b_type) {
  const size_t kBufSize = 40;
  char aval_str[kBufSize];
  char bval_str[kBufSize];
  // If the expected value is written as hex, print the actual value as hex too.
  if (a_type == PRINT_HEX ||
      kstrncmp(astr, "0x", 2) == 0 || kstrncmp(bstr, "0x", 2) == 0) {
    // Get around the fact that ksprintf() can't do 64-bit numbers on 32-bit
    // platforms :/  Note that this truncates anyway when the intmax_t is passed
    // to kutoa_hex_r.
    // TODO(aoates): figure out 64-bit versions of the kstring functions on
    // 32-bit platforms and make them work.
    kstrcpy(aval_str, "0x");
    kutoa_hex_r(aval, aval_str + 2, kBufSize - 2);
    kstrcpy(bval_str, "0x");
    kutoa_hex_r(bval, bval_str + 2, kBufSize - 2);
  } else if (b_type == PRINT_SIGNED ||
             kstrncmp(astr, "-", 1) == 0 || kstrncmp(bstr, "-", 1) == 0) {
    kexpect_int_to_string(aval, bval, aval_str, bval_str, kBufSize);
  } else {
    kutoa_r(aval, aval_str, kBufSize);
    kutoa_r(bval, bval_str, kBufSize);
  }
  return kexpect(result, name, astr, bstr, aval_str, bval_str, "", opstr, file,
                 line);
}

void ktest_add_failure(const char* file, const char* line, const char* msg) {
  do_failure();
  klogm(KL_TEST, INFO, FAILED " Failure at ");
  klogm(KL_TEST, INFO, file);
  klogm(KL_TEST, INFO, ":");
  klogm(KL_TEST, INFO, line);
  klogm(KL_TEST, INFO, ": ");
  klogm(KL_TEST, INFO, msg);
  klogm(KL_TEST, INFO, "\n");
}

void ktest_add_failuref(const char* file, const char* line, const char* fmt,
                        ...) {
  char buf[200];
  va_list args;
  va_start(args, fmt);
  int r = kvsnprintf(buf, 200, fmt, args);
  va_end(args);
  if (r == 200) {
    klog("warning: buffer too small in ktest_add_failuref()\n");
  }
  ktest_add_failure(buf, file, line);
}

static void cpy_or_trunc(char* dst, const char* start, size_t strlen,
                         size_t buflen) {
  if (strlen + 1 < buflen) {
    kstrncpy(dst, start, strlen);
    dst[strlen] = '\0';  // Shouldn't cpy do this?
  } else {
    ksprintf(dst, "<too long (%zu bytes)>", strlen);
  }
}

bool kexpect_multiline_streq(const char* file, const char* line,
                             const char* astr, const char* bstr,
                             const char* aval, const char* bval) {
  int result = !kstrcmp(aval, bval);
  char buf1[30], buf2[30];
  ksprintf(buf1, "<%d-byte string>", kstrlen(aval));
  ksprintf(buf2, "<%d-byte string>", kstrlen(bval));
  kexpect(result, "KEXPECT_MULTILINE_STREQ", astr, bstr, buf1, buf2, "",
          " == ", file, line);
  if (result == 0) {
    // If this gets used a lot, should switch to a proper LCS/diff algorithm.
    const ssize_t kBufSize = 1000;
    char* buf = (char*)kmalloc(kBufSize);
    int cline = 0, badlines = 0;
    while (*aval && *bval) {
      const char* aend = kstrchrnul(aval, '\n');
      const char* bend = kstrchrnul(bval, '\n');
      if ((aend - aval) != (bend - bval) ||
          kstrncmp(aval, bval, aend - aval) != 0) {
        klogfm(KL_TEST, INFO, "Mismatch on line %d: ", cline);
        cpy_or_trunc(buf, aval, aend - aval, kBufSize);
        klogfm(KL_TEST, INFO, "'%s' != ", buf);
        cpy_or_trunc(buf, bval, bend - bval, kBufSize);
        klogfm(KL_TEST, INFO, "'%s'\n", buf);
        badlines++;
      } else {
        badlines = 0;
      }
      // If we've seen more than a few bad lines in a row, bail.
      if (badlines > 3) {
        klogfm(KL_TEST, INFO, "(stopping comparison, too many mismatches)\n");
        break;
      }
      aval = aend;
      bval = bend;
      if (*aval == '\n') aval++;
      if (*bval == '\n') bval++;
      cline++;
    }
    kfree(buf);
  }
  return result;
}

void ktest_begin_all(void) {
  num_suites = 0;
  num_tests = 0;
  num_suites_passing = 0;
  num_tests_passing = 0;
  current_suite_passing = 0;
  current_test_passing = 0;
  current_test_failures = 0;
  failing_test_names_idx = 0;
  test_start_time = get_time_ms();

  KLOG("KERNEL UNIT TESTS");
}

void ktest_finish_all(void) {
  // Trigger the block cache flush thread to flush any dirtied blocks from the
  // end of the test run (e.g. cleanup operations), in case we're terminated
  // immediately after this.
  block_cache_quiesce_flushing(200);

  apos_ms_t end_time = get_time_ms();
  finish_test();
  finish_suite();

  KLOG("---------------------------------------\n");
  if (num_suites == num_suites_passing) {
    KLOG(PASSED " passed %d/%d suites and %d/%d tests in %d ms\n",
         num_suites_passing, num_suites, num_tests_passing, num_tests,
         end_time - test_start_time);
  } else {
    KLOG(FAILED " passed %d/%d suites and %d/%d tests in %d ms\n",
         num_suites_passing, num_suites, num_tests_passing, num_tests,
         end_time - test_start_time);
    KLOG("Failed tests:\n");
    for (int i = 0; i < failing_test_names_idx; ++i) {
      KLOG("  %s\n", failing_test_names[i]);
    }
    int num_leftover = num_tests - num_tests_passing - failing_test_names_idx;
    if (num_leftover > 0) {
      KLOG("  ...and %d more\n", num_leftover);
    }
  }
  KEXPECT_EQ(0, test_point_count());
  KLOG("KERNEL UNIT TESTS FINISHED\n");
  KLOG("---------------------------------------\n");
}

int ktest_current_test_failures(void) {
  return current_test_failures;
}
