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

#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>

#include <apos/sleep.h>

#include "ktest.h"
#include "all_tests.h"

static bool got_signal = false;
static void signal_action(int sig) {
  printf("caught signal\n");
  got_signal = true;
}

static void alarm_test(void) {
  KTEST_BEGIN("alarm() test");
  got_signal = false;

  struct sigaction new_action, old_action;
  new_action.sa_handler = &signal_action;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;
  KEXPECT_EQ(0, sigaction(SIGALRM, &new_action, &old_action));
  alarm(1);
  sleep(2);  // TODO(aoates): use usleep

  KEXPECT_EQ(true, got_signal);

  KEXPECT_EQ(0, sigaction(SIGALRM, &old_action, NULL));
}

static void signal_test(void) {
  KTEST_BEGIN("cross-process signal test");
  got_signal = false;

  pid_t child;
  if (!(child = fork())) {
    struct sigaction new_action;
    new_action.sa_handler = &signal_action;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;

    int result = sigaction(SIGUSR1, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    sleep_ms(200);
    exit(got_signal ? 0 : 1);
  }

  // In parent.
  sleep_ms(100);  // Let the child run.  Not really safe.
  kill(child, SIGUSR1);
  int exit_status;
  KEXPECT_EQ(child, wait(&exit_status));
  KEXPECT_EQ(0, exit_status);
}

void basic_signal_test(void) {
  KTEST_SUITE_BEGIN("basic signal tests");

  if (run_slow_tests) {
    alarm_test();
  }

  signal_test();
}
