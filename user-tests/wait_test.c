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

#include <sys/signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#include "ktest.h"

static void exit_status_test(void) {
  KTEST_BEGIN("Exit status macros (normal status)");
  const int statuses[6] = {0, 1, 2, 10, 65, 127};
  for (int i = 0; i < 6; ++i) {
    pid_t child = fork();
    if (child == 0) {
      exit(statuses[i]);
    }
    int status;
    KEXPECT_EQ(child, waitpid(child, &status, 0));
    KEXPECT_NE(0, WIFEXITED(status));
    KEXPECT_EQ(statuses[i], WEXITSTATUS(status));
    KEXPECT_EQ(0, WIFSIGNALED(status));
    KEXPECT_EQ(0, WIFSTOPPED(status));
    KEXPECT_EQ(0, WIFCONTINUED(status));
  }

  KTEST_BEGIN("Exit status macros (terminated with signal)");
  const int term_sigs[3] = {SIGKILL, SIGQUIT, SIGUSR1};
  for (int i = 0; i < 3; ++i) {
    pid_t child = fork();
    if (child == 0) {
      sleep(1);
      exit(0);
    }
    KEXPECT_EQ(0, kill(child, term_sigs[i]));
    int status;
    KEXPECT_EQ(child, wait(&status));

    KEXPECT_EQ(0, WIFEXITED(status));
    KEXPECT_NE(0, WIFSIGNALED(status));
    KEXPECT_EQ(term_sigs[i], WTERMSIG(status));
    KEXPECT_EQ(0, WIFSTOPPED(status));
    KEXPECT_EQ(0, WIFCONTINUED(status));
  }
}

void wait_test(void) {
  KTEST_SUITE_BEGIN("wait() and waitpid() tests");
  exit_status_test();
}
