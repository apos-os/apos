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

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

#include "os/common/apos_klog.h"
#include "user/include/apos/auxvec.h"

#include "ktest.h"

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

static int test_start_time;

static const char* current_test_name = 0x0;

void* INVALID_ADDR;

// Array of failing test names.  Assumes that test names aren't generated on the
// fly (i.e. the pointers we get to them in KTEST_BEGIN() stay good).
#define FAILING_TEST_NAMES_LEN 100
static const char* failing_test_names[FAILING_TEST_NAMES_LEN];
static int failing_test_names_idx = 0;

// Convert two integer values into strings, appending the errorname if it looks
// like an error code is being returned (one of the operands is zero, and the
// other is between -ERRNO_MIN and -ERRNO_MAX).
static inline void kexpect_int_to_string(int aval, int bval, char* aval_str,
                                         char* bval_str) {
  const int aval_in_range = 0; //aval >= -ERRNO_MAX && aval <= -ERRNO_MIN;
  const int bval_in_range = 0; //bval >= -ERRNO_MAX && bval <= -ERRNO_MIN;

  sprintf(aval_str, "%d", aval);
  if ((bval_in_range || bval == 0) && aval_in_range) {
    strcat(aval_str, " (");
    strcat(aval_str, strerror(-aval));
    strcat(aval_str, ")");
  }
  sprintf(bval_str, "%d", bval);
  if ((aval_in_range || aval == 0) && bval_in_range) {
    strcat(bval_str, " (");
    strcat(bval_str, strerror(-bval));
    strcat(bval_str, ")");
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
  apos_klogf("\n\nTEST SUITE: %s\n", name);
  apos_klogf("#######################################\n");
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
      apos_klogf("\nTEST: %s\n", current_test_name);
      apos_klogf("---------------------------------------\n");
    }
    current_test_passing = 0;
    current_suite_passing = 0;
    apos_klogf(FAILED " %s(%s, %s) at %s:%s: %s%s%s%s%s%s%s\n", name, astr,
               bstr, file, line, val_surrounders, aval, val_surrounders, opstr,
               val_surrounders, bval, val_surrounders);
  }
}

void kexpect_int(const char* name, const char* file, const char* line,
                 const char* astr, const char* bstr, long aval, long bval,
                 long result, const char* opstr, kexpect_print_t a_type,
                 kexpect_print_t b_type) {
  char aval_str[20];
  char bval_str[20];
  // If the expected value is written as hex, print the actual value as hex too.
  if (a_type == PRINT_HEX ||
      strncmp(astr, "0x", 2) == 0 || strncmp(bstr, "0x", 2) == 0) {
    sprintf(aval_str, "%#x", (int)aval);
    sprintf(bval_str, "%#x", (int)bval);
  } else if (b_type == PRINT_SIGNED ||
             strncmp(astr, "-", 1) == 0 || strncmp(bstr, "-", 1) == 0) {
    kexpect_int_to_string((int)aval, (int)bval, aval_str, bval_str);
  } else {
    sprintf(aval_str, "%d", (int)aval);
    sprintf(bval_str, "%d", (int)bval);
  }
  kexpect(result, name, astr, bstr, aval_str, bval_str, "", opstr, file, line);
}

static void cpy_or_trunc(char* dst, const char* start, size_t strlen,
                         size_t buflen) {
  if (strlen + 1 < buflen) {
    strncpy(dst, start, strlen);
    dst[strlen] = '\0';  // Shouldn't cpy do this?
  } else {
    sprintf(dst, "<too long (%zu bytes)>", strlen);
  }
}

static const char* kstrchrnul(const char* s, int c) {
  while (*s) {
    if (*s == c) {
      return s;
    }
    s++;
  }
  return s;
}

bool kexpect_multiline_streq(const char* file, const char* line,
                             const char* astr, const char* bstr,
                             const char* aval, const char* bval) {
  int result = !strcmp(aval, bval);
  char buf1[30], buf2[30];
  sprintf(buf1, "<%d-byte string>", (int)strlen(aval));
  sprintf(buf2, "<%u-byte string>", (int)strlen(bval));
  kexpect(result, "KEXPECT_MULTILINE_STREQ", astr, bstr, buf1, buf2, "",
          " == ", file, line);
  if (result == 0) {
    // If this gets used a lot, should switch to a proper LCS/diff algorithm.
    const ssize_t kBufSize = 1000;
    char* buf = (char*)malloc(kBufSize);
    int cline = 0, badlines = 0;
    while (*aval && *bval) {
      const char* aend = kstrchrnul(aval, '\n');
      const char* bend = kstrchrnul(bval, '\n');
      if ((aend - aval) != (bend - bval) ||
          strncmp(aval, bval, aend - aval) != 0) {
        apos_klogf("Mismatch on line %d: ", cline);
        cpy_or_trunc(buf, aval, aend - aval, kBufSize);
        apos_klogf("'%s' != ", buf);
        cpy_or_trunc(buf, bval, bend - bval, kBufSize);
        apos_klogf("'%s'\n", buf);
        badlines++;
      } else {
        badlines = 0;
      }
      // If we've seen more than a few bad lines in a row, bail.
      if (badlines > 3) {
        apos_klogf("(stopping comparison, too many mismatches)\n");
        break;
      }
      aval = aend;
      bval = bend;
      if (*aval == '\n') aval++;
      if (*bval == '\n') bval++;
      cline++;
    }
    free(buf);
  }
  return result;
}

void ktest_begin_all(void) {
  if (INVALID_ADDR == 0) {
    const size_t kMapSize = 64 * 1024 * 1024;
    void* result = mmap((void*)0xf234567, kMapSize, PROT_READ,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(result != MAP_FAILED);
    // Make the second-to-last page our invalid address, and unmap everything
    // except the pages surrounding that page.  This should hopefully minimize
    // the likelihood that another mapping will take our invalid address.
    const size_t PAGE_SIZE = apos_auxval_get(AUXVEC_PAGESZ);
    INVALID_ADDR = result + kMapSize - PAGE_SIZE;
    assert(0 == munmap(result, kMapSize - 3 * PAGE_SIZE));
    assert(0 == munmap(INVALID_ADDR, PAGE_SIZE));
    apos_klogf("Picked INVALID_ADDR of %p\n", INVALID_ADDR);
  }
  num_suites = 0;
  num_tests = 0;
  num_suites_passing = 0;
  num_tests_passing = 0;
  current_suite_passing = 0;
  current_test_passing = 0;
  failing_test_names_idx = 0;
  test_start_time = 0;  // TODO get_time_ms();

  apos_klogf("USERSPACE UNIT TESTS");
}

int ktest_finish_all(void) {
  int end_time = 0;  // TODO get_time_ms();
  finish_test();
  finish_suite();

  apos_klogf("---------------------------------------\n");
  apos_klogf("USERSPACE UNIT TESTS FINISHED\n");
  if (num_suites == num_suites_passing) {
    apos_klogf(PASSED
               " passed (user-mode) %d/%d suites and %d/%d tests in %d ms\n",
               num_suites_passing, num_suites, num_tests_passing, num_tests,
               end_time - test_start_time);
    return 0;
  } else {
    apos_klogf(FAILED
               " passed (user-mode) %d/%d suites and %d/%d tests in %d ms\n",
               num_suites_passing, num_suites, num_tests_passing, num_tests,
               end_time - test_start_time);
    apos_klogf("Failed tests:\n");
    for (int i = 0; i < failing_test_names_idx; ++i) {
      apos_klogf("  %s\n", failing_test_names[i]);
    }
    int num_leftover = num_tests - num_tests_passing - failing_test_names_idx;
    if (num_leftover > 0) {
      apos_klogf("  ...and %d more\n", num_leftover);
    }
    return 1;
  }
}
