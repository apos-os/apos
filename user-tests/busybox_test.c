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
// A test suite that exercises basic busybox functionality.
#include <ctype.h>
#include <sys/unistd.h>

#include "all_tests.h"
#include "ktest.h"

#define BUF_SIZE 1000
#define STDOUT_FILE "_bbtest_stdout.txt"
#define STDERR_FILE "_bbtest_stderr.txt"

typedef struct {
  int status;
  char out[BUF_SIZE];
  char err[BUF_SIZE];
} cmd_result_t;

static int run_bb(const char* cmd[], cmd_result_t* result) {
  int stdout_fd = open(STDOUT_FILE, O_RDWR | O_CREAT | O_TRUNC, VFS_S_IRWXU);
  KEXPECT_GE(stdout_fd, 0);
  int stderr_fd = open(STDERR_FILE, O_RDWR | O_CREAT | O_TRUNC, VFS_S_IRWXU);
  KEXPECT_GE(stderr_fd, 0);

  pid_t child = fork();
  if (child == 0) {
    // In the child.  Redirect stdout/stderr and run the command.
    dup2(stdout_fd, 1);
    dup2(stderr_fd, 2);
    size_t args;
    for (args = 0; cmd[args] != NULL; ++args);
    char** argv = malloc(sizeof(char*) * args + 1);
    for (size_t i = 0; i < args; ++i) {
      argv[i] = strdup(cmd[i]);
    }
    argv[args] = NULL;
    execv("/bin/busybox", argv);
    apos_klog("UNEXPECTED: execv failed in busybox test\n");
    exit(1);
  }

  KEXPECT_EQ(child, waitpid(child, &result->status, 0));

  // Read stdout and stderr.
  KEXPECT_EQ(0, lseek(stdout_fd, 0, SEEK_SET));
  ssize_t bytes = read(stdout_fd, result->out, BUF_SIZE - 1);
  KEXPECT_GE(bytes, 0);
  KEXPECT_LT(bytes, BUF_SIZE - 1);  // Make sure buffer is big enough.
  result->out[bytes] = 0;
  KEXPECT_EQ(0, close(stdout_fd));
  KEXPECT_EQ(0, unlink(STDOUT_FILE));

  KEXPECT_EQ(0, lseek(stderr_fd, 0, SEEK_SET));
  bytes = read(stderr_fd, result->err, BUF_SIZE - 1);
  KEXPECT_GE(bytes, 0);
  KEXPECT_LT(bytes, BUF_SIZE - 1);  // Make sure buffer is big enough.
  result->err[bytes] = 0;
  KEXPECT_EQ(0, close(stderr_fd));
  KEXPECT_EQ(0, unlink(STDERR_FILE));
  return result->status;
}

static char* stripr(char* str) {
  size_t len = strlen(str);
  while (len > 0 && isspace((int)str[len - 1])) {
    str[len - 1] = '\0';
    len--;
  }
  return str;
}

static void date_test(void) {
  KTEST_BEGIN("busybox date test");
  cmd_result_t res;
  KEXPECT_EQ(0, run_bb((const char*[])
                       {"date", "-u", "-d", "2025-11-01-12:52:15", NULL},
                       &res));
  KEXPECT_STREQ(stripr(res.out), "Fri Oct 31 12:52:15 UTC 2025");

  KEXPECT_EQ(1, run_bb((const char*[])
                       {"date", "-u", "-d", "-1234", NULL},
                       &res));
  KEXPECT_STREQ(stripr(res.err), "date: invalid date '-1234'");
}

void busybox_tests(void) {
  KTEST_SUITE_BEGIN("busybox tests");
  date_test();
}
