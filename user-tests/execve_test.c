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

#include <apos/sleep.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ktest.h"
#include "all_tests.h"
#include "user/include/apos/auxvec.h"

#define EXEC_PROGRAM "/bin/ls"
#define SELF_PROGRAM "/bin/all_tests"
#define EXECVE_HELPER "execve_test_helper"
#define AUXV_TEST_PROGRAM "/bin/auxv_test"

static int do_execve(const char* path, char* const* argv, char* const* envp) {
  int result = execve(path, argv, envp);
  if (result)
    return -errno;
  return 0;
}

int execve_helper(int argc, char** argv) {
  if (argc < 2) {
    printf("error: incorrect number of arguments to execve_test_helper\n");
    return 1;
  }

  if (strcmp(argv[1], "argv_test") == 0) {
    if (argc != 5) {
      printf("error: incorrect number of arguments in execve() argv test\n");
      return 1;
    }
    const char* kExpected[] = {"abcdef", "123", "X"};
    for (int i = 0; i < 3; ++i) {
      if (strcmp(argv[2 + i], kExpected[i]) != 0) {
        printf("error: bad argument #%d to execve() argv test (expected '%s', "
               "got '%s')\n", i, kExpected[i], argv[2 + i]);
        return 1;
      }
    }
    return 0;
  } else if (strcmp(argv[1], "sleep") == 0) {
    if (argc != 3) {
      printf("error: incorrect number of arguments in execve() sleep\n");
      return 1;
    }
    int len_ms = atoi(argv[2]);
    printf("sleeping for %d ms\n", len_ms);
    sleep_ms(len_ms);
    return 0;
  } else if (strcmp(argv[1], "read_bad_fd_15") == 0) {
    struct stat stat;
    int result = fstat(15, &stat);
    if (result == 0 || errno != EBADF) {
      printf("error: fstat() didn't return -EBADF\n");
      return 1;
    }
    return 0;
  }

  printf("error: bad subcommand in execve() test helper: '%s'\n", argv[1]);
  return 1;
}

static void basic_execve_test(void) {
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

static int do_execve_expect_term(const char* path, char* const* argv, char* const* envp) {
  pid_t child = fork();
  if (child == 0) {
    do_execve(path, argv, envp);
    exit(1);
  }
  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  return WTERMSIG(status);
}

static void execve_args_test(void) {
  KTEST_BEGIN("execve() basic argv test");

  pid_t child;
  if ((child = fork()) == 0) {
    char* sub_argv[] = {EXECVE_HELPER, "argv_test", "abcdef", "123", "X", NULL};
    char* sub_envp[] = {NULL};
    int result = execve(SELF_PROGRAM, sub_argv, sub_envp);
    if (result) {
      perror("execve failed");
      exit(1);
    }
  }

  int status = 0;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("execve() bad path test");
  char* argv_ok[] = {"argv0", NULL};
  char* envp_ok[] = {"envp0", NULL};
  KEXPECT_EQ(-EINVAL, do_execve(NULL, argv_ok, envp_ok));
  KEXPECT_EQ(SIGSEGV,
             do_execve_expect_term((const char*)0x5fff, argv_ok, envp_ok));
  KEXPECT_EQ(SIGSEGV,
             do_execve_expect_term((const char*)0xe0000000, argv_ok, envp_ok));

  KTEST_BEGIN("execve() bad argv test");
  char* bad_argvA[] = {"A", "B", (char*)0x5fff, NULL};
  char* bad_argvB[] = {"A", "B", (char*)0xe0000000, NULL};
  KEXPECT_EQ(-EINVAL, do_execve("path", NULL, envp_ok));
  KEXPECT_EQ(-EFAULT, do_execve("path", (char* const*)0x5fff, envp_ok));
  KEXPECT_EQ(-EFAULT, do_execve("path", (char* const*)0xc1000000, envp_ok));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term(
                          "path", (char* const*)&execve_args_test, envp_ok));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term("path", bad_argvA, envp_ok));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term("path", bad_argvB, envp_ok));

  KTEST_BEGIN("execve() bad envp test");
  KEXPECT_EQ(-EINVAL, do_execve("path", argv_ok, NULL));
  KEXPECT_EQ(-EFAULT, do_execve("path", argv_ok, (char* const*)0x5fff));
  KEXPECT_EQ(-EFAULT, do_execve("path", argv_ok, (char* const*)0xc1000000));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term("path", argv_ok,
                                            (char* const*)&execve_args_test));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term("path", argv_ok, bad_argvA));
  KEXPECT_EQ(SIGSEGV, do_execve_expect_term("path", argv_ok, bad_argvB));
}

static void cloexec_test(void) {
  KTEST_BEGIN("execve(): O_CLOEXEC test");
  KEXPECT_EQ(15, dup2(0, 15));
  KEXPECT_EQ(0, fcntl(15, F_GETFD, 0));
  KEXPECT_EQ(0, fcntl(15, F_SETFD, O_CLOEXEC));
  KEXPECT_EQ(O_CLOEXEC, fcntl(15, F_GETFD, 0));

  pid_t child = fork();
  if (child == 0) {
    if (fcntl(15, F_GETFD, 0) != O_CLOEXEC) {
      printf("error: O_CLOEXEC not set after fork\n");
      exit(1);
    }
    char* sub_argv[] = {EXECVE_HELPER, "read_bad_fd_15", NULL};
    char* sub_envp[] = {NULL};
    int result = execve(SELF_PROGRAM, sub_argv, sub_envp);
    if (result) {
      perror("execve failed");
    }
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_EQ(0, status);
  KEXPECT_EQ(0, close(15));
}

const apos_auxv_t* apos_auxv_get_raw(void);
static void auxv_test(void) {
  KTEST_BEGIN("execve(): auxvec data passed correctly");
  bool auxv_seen[AUXVEC_MAX + 1];
  uint64_t auxv_vals[AUXVEC_MAX + 1];
  memset(&auxv_seen, 0, sizeof(auxv_seen));
  memset(&auxv_vals, 0, sizeof(auxv_vals));

  const apos_auxv_t* auxv = apos_auxv_get_raw();
  for (; auxv->a_type != AUXVEC_NULL; ++auxv) {
    KEXPECT_LE(auxv->a_type, AUXVEC_MAX);
    if (auxv->a_type > AUXVEC_MAX) continue;

    KEXPECT_FALSE(auxv_seen[auxv->a_type]);  // Should only see each once.
    auxv_vals[auxv->a_type] = auxv->a_val + ((uint64_t)auxv->a_val_hi << 32);
    auxv_seen[auxv->a_type] = true;
  }
  KEXPECT_TRUE(auxv_seen[AUXVEC_BASE]);
  KEXPECT_TRUE(auxv_seen[AUXVEC_PAGESZ]);
  KEXPECT_EQ(0, auxv_vals[AUXVEC_BASE]);
  KEXPECT_EQ(0, apos_auxval_get(AUXVEC_BASE));
  KEXPECT_EQ(4096, auxv_vals[AUXVEC_PAGESZ]);
  KEXPECT_EQ(4096, apos_auxval_get(AUXVEC_PAGESZ));
}

void execve_test(void) {
  KTEST_SUITE_BEGIN("execve() test");

  basic_execve_test();
  execve_args_test();
  cloexec_test();
  auxv_test();
  // TODO(aoates): test envp functionality.
  // TODO(aoates): test too-large argv and envp tables.
}
