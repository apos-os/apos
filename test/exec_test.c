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

#include "common/errno.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/vfs.h"

static void do_exec_mode_test(void* arg) {
  const char kFile[] = "exec_mode_test/file";

  char* const argv[] = {"f"};
  char* const envp[] = {};

  KTEST_BEGIN("exec(): root can't exec() if no exec bits are set");
  create_file(kFile, "rw-rw-rw-");
  KEXPECT_EQ(-EACCES, do_execve(kFile, argv, envp, NULL, NULL));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KEXPECT_EQ(0, setregid(1, 2));
  KEXPECT_EQ(0, setreuid(3, 4));

  KTEST_BEGIN("exec(): fails on non-readable file");
  create_file(kFile, "-wxrwxrwx");
  KEXPECT_EQ(-EACCES, do_execve(kFile, argv, envp, NULL, NULL));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("exec(): \"succeeds\" on non-writable file");
  create_file(kFile, "r-xrwxrwx");
  KEXPECT_EQ(-ENOEXEC, do_execve(kFile, argv, envp, NULL, NULL));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("exec(): fails on non-executable file");
  create_file(kFile, "rw-rwxrwx");
  KEXPECT_EQ(-EACCES, do_execve(kFile, argv, envp, NULL, NULL));
  KEXPECT_EQ(0, vfs_unlink(kFile));
}

// Verify that do_exec() won't execute a non-executable or non-readable file,
// but will execute a writable file.
static void exec_mode_test(void) {
  const char kDir[] = "exec_mode_test";

  KTEST_BEGIN("exec(): mode test setup");
  KEXPECT_EQ(0, vfs_mkdir(kDir, str_to_mode("rwxrwxrwx")));

  pid_t child_pid = proc_fork(&do_exec_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KTEST_BEGIN("exec(): mode test teardown");
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

void exec_test(void) {
  KTEST_SUITE_BEGIN("exec() tests");

  exec_mode_test();

  // TODO(aoates): do much more extensive tests, including,
  //  * bad path
  //  * execing a directory
  //  * valid executable
  //  * cleanup function is called
  //  * various bad ELF file tests.
}
