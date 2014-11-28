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
#include <sys/wait.h>

#include "ktest.h"
#include "all_tests.h"

#define EXEC_PROGRAM "ls"

void execve_test(void) {
  KTEST_SUITE_BEGIN("execve() test");
  KTEST_BEGIN("execve() ls test");

  pid_t child;
  if ((child = fork()) == 0) {
    char* sub_argv[] = {EXEC_PROGRAM, NULL};
    char* sub_envp[] = {NULL};
    int result = execve(EXEC_PROGRAM, sub_argv, sub_envp);
    if (result) {
      perror("execve failed");
      exit(1);
    }
  }

  int status = 0;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}
