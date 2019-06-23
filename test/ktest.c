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
#include "dev/timer.h"

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
static inline void kexpect_int_to_string(long aval, long bval, char* aval_str,
                                         char* bval_str) {
  const int aval_in_range = aval >= -ERRNO_MAX && aval <= -ERRNO_MIN;
  const int bval_in_range = bval >= -ERRNO_MAX && bval <= -ERRNO_MIN;

  kstrcpy(aval_str, itoa(aval));
  if ((bval_in_range || bval == 0) && aval_in_range) {
    kstrcat(aval_str, " (");
    kstrcat(aval_str, errorname(-aval));
    kstrcat(aval_str, ")");
  }
  kstrcpy(bval_str, itoa(bval));
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
  num_tests++;
}

void kexpect(int cond, const char* name, const char* astr,
             const char* bstr, const char* aval, const char* bval,
             const char* val_surrounders, const char* opstr, const char* file,
             const char* line) {
  if (!cond) {
    if (current_test_passing) {
      klogm(KL_TEST, INFO, "\nTEST: ");
      klogm(KL_TEST, INFO, current_test_name);
      klogm(KL_TEST, INFO, "\n");
      klogm(KL_TEST, INFO, "---------------------------------------\n");
    }
    current_test_passing = 0;
    current_suite_passing = 0;
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
}

void kexpect_int(const char* name, const char* file, const char* line,
                 const char* astr, const char* bstr, long aval, long bval,
                 long result, const char* opstr, kexpect_print_t a_type,
                 kexpect_print_t b_type) {
  char aval_str[40];
  char bval_str[40];
  // If the expected value is written as hex, print the actual value as hex too.
  if (a_type == PRINT_HEX ||
      kstrncmp(astr, "0x", 2) == 0 || kstrncmp(bstr, "0x", 2) == 0) {
    ksprintf(aval_str, "0x%s", utoa_hex(aval));
    ksprintf(bval_str, "0x%s", utoa_hex(bval));
  } else if (b_type == PRINT_SIGNED ||
             kstrncmp(astr, "-", 1) == 0 || kstrncmp(bstr, "-", 1) == 0) {
    kexpect_int_to_string(aval, bval, aval_str, bval_str);
  } else {
    kstrcpy(aval_str, utoa(aval));
    kstrcpy(bval_str, utoa(bval));
  }
  kexpect(result, name, astr, bstr, aval_str, bval_str, "", opstr, file, line);
}

void ktest_begin_all() {
  num_suites = 0;
  num_tests = 0;
  num_suites_passing = 0;
  num_tests_passing = 0;
  current_suite_passing = 0;
  current_test_passing = 0;
  failing_test_names_idx = 0;
  test_start_time = get_time_ms();

  KLOG("KERNEL UNIT TESTS");
}

void ktest_finish_all() {
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
  KLOG("KERNEL UNIT TESTS FINISHED\n");
  KLOG("---------------------------------------\n");
}
