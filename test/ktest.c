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

#include "common/kstring.h"
#include "common/klog.h"

// Track statistics about passing and failing tests.
static int num_suites = 0;
static int num_tests = 0;
static int num_suites_passing = 0;
static int num_tests_passing = 0;

// Is the current suite/test passing?
static int current_suite_passing = 0;
static int current_test_passing = 0;

static void finish_test() {
  if (current_test_passing) {
    num_tests_passing++;
  }
}

static void finish_suite() {
  if (current_suite_passing) {
    num_suites_passing++;
  }
}

void KTEST_SUITE_BEGIN(const char* name) {
  finish_suite();  // Finish the previous suite, if running.
  current_suite_passing = 1;
  num_suites++;
  klog("\n\nTEST SUITE: ");
  klog(name);
  klog("\n");
  klog("#######################################\n");
}

void KTEST_BEGIN(const char* name) {
  finish_test();  // Finish the previous test, if running.
  current_test_passing = 1;
  num_tests++;
  klog("\nTEST: ");
  klog(name);
  klog("\n");
  klog("---------------------------------------\n");
}

void kexpect_(uint32_t cond, const char* name,
              const char* astr, const char* bstr,
              const char* aval, const char* bval,
              const char* opstr,
              const char* file, const char* line) {
  if (cond) {
    klog("[PASSED] ");
    klog(name);
    klog("(");
    klog(astr);
    klog(", ");
    klog(bstr);
    klog(")\n");
  } else {
    current_test_passing = 0;
    current_suite_passing = 0;
    klog("[FAILED] ");
    klog(name);
    klog("(");
    klog(astr);
    klog(", ");
    klog(bstr);
    klog(") at ");
    klog(file);
    klog(":");
    klog(line);
    klog(": ");
    klog(aval);
    klog(opstr);
    klog(bval);
    klog("\n");
  }
}

void ktest_begin_all() {
  klogf("KERNEL UNIT TESTS");
}

void ktest_finish_all() {
  finish_test();
  finish_suite();

  klogf("---------------------------------------\n");
  klogf("KERNEL UNIT TESTS FINISHED\n");
  if (num_suites == num_suites_passing) {
    klogf("[PASSED] passed %d/%d suites and %d/%d tests\n",
          num_suites_passing, num_suites, num_tests_passing, num_tests);
  } else {
    klogf("[FAILED] passed %d/%d suites and %d/%d tests\n",
          num_suites_passing, num_suites, num_tests_passing, num_tests);
  }
}
