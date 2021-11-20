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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ktest.h"
#include "all_tests.h"

#define ERRNO_TEST(call, expected_retval, expected_errno) do { \
  errno = 0; \
  typeof(call) retval = call; \
  int error = errno; \
  KEXPECT_EQ(expected_retval, retval); \
  KEXPECT_EQ(expected_errno, error); \
} while (0);

void syscall_errno_test() {
  char buf[100];
  KTEST_SUITE_BEGIN("syscall errno setting");

  KTEST_BEGIN("close() errno");
  ERRNO_TEST(close(-5), -1, EBADF);

  KTEST_BEGIN("mkdir() errno");
  ERRNO_TEST(mkdir(NULL, S_IRWXU), -1, EINVAL);
  pid_t child = fork();
  if (child == 0) {
    mkdir((const char*)0x1234, S_IRWXU);  // Should generate SIGSEGV.
    exit(1);
  }
  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));
  ERRNO_TEST(mkdir("/does/not/exist", S_IRWXU), -1, ENOENT);

  KTEST_BEGIN("mknod() errno");
  ERRNO_TEST(mknod(NULL, S_IRWXU, 0), -1, EINVAL);

  KTEST_BEGIN("rmdir() errno");
  ERRNO_TEST(rmdir(NULL), -1, EINVAL);
  ERRNO_TEST(rmdir("/does/not/exist"), -1, ENOENT);

  KTEST_BEGIN("unlink() errno");
  ERRNO_TEST(unlink(NULL), -1, EINVAL);
  ERRNO_TEST(unlink("/does/not/exist"), -1, ENOENT);

  KTEST_BEGIN("read() errno");
  ERRNO_TEST(read(-5, buf, 100), -1, EBADF);

  KTEST_BEGIN("write() errno");
  ERRNO_TEST(write(-5, buf, 100), -1, EBADF);

  KTEST_BEGIN("lseek() errno");
  ERRNO_TEST(lseek(-5, 0, SEEK_CUR), -1, EBADF);
  ERRNO_TEST(lseek(0, 0, 1234), -1, EINVAL);

  // Tests for syscalls that have custom wrappers.
  KTEST_BEGIN("open() errno");
  ERRNO_TEST(open("does_not_exist", O_RDONLY), -1, ENOENT);

  child = fork();
  if (child == 0) {
    open((const char*)0x1234, O_RDONLY);  // Should generate SIGSEGV.
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));


  KTEST_BEGIN("getcwd() errno");
  ERRNO_TEST(getcwd(NULL, 100), NULL, EFAULT);
  ERRNO_TEST(getcwd((char*)0x1234, 100), NULL, EFAULT);

  KEXPECT_EQ(&buf[0], getcwd(buf, 100));

  KTEST_BEGIN("mmap() errno");
  ERRNO_TEST(mmap(0x0, 1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
             NULL,
             EINVAL);
}
