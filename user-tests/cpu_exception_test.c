// Copyright 2016 Andrew Oates.  All Rights Reserved.
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
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <time.h>

#include "ktest.h"
#include "all_tests.h"

static struct sigaction make_sigaction(void (*handler)(int)) {
  struct sigaction new_action;
  new_action.sa_handler = handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;
  return new_action;
}

static void catch_sigsegv(int sig) {
  // TODO(aoates): test the signal metadata, once that's generated.
  exit(!(sig == SIGSEGV));
}

static void gp_fault_test(void) {
  KTEST_BEGIN("GP fault handling");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction new_action = make_sigaction(&catch_sigsegv);
    int result = sigaction(SIGSEGV, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    asm volatile ("cli\n\t");

    fprintf(stderr, "Got past segfault!\n");
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void lcall_ldt_test(void) {
  KTEST_BEGIN("lcall to bad LDT fault handling");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction new_action = make_sigaction(&catch_sigsegv);
    int result = sigaction(SIGSEGV, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    asm volatile ("lcall  $0x76, $0\n\t");

    fprintf(stderr, "Got past segfault!\n");
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

void cpu_exception_test(void) {
  KTEST_SUITE_BEGIN("CPU exception tests");

  gp_fault_test();
  lcall_ldt_test();
}
