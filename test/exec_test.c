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

#include "common/arch-config.h"
#include "common/errno.h"
#include "proc/exec.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/vfs/stat.h"
#include "vfs/vfs.h"

static void do_exec_mode_test(void* arg) {
  const char kFile[] = "exec_mode_test/file";

  char* const argv[] = {"f", NULL};
  char* const envp[] = {NULL};

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

  kpid_t child_pid = proc_fork(&do_exec_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KTEST_BEGIN("exec(): mode test teardown");
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

typedef struct {
  char bin[20];
  kmutex_t mu;
  kthread_queue_t q GUARDED_BY(&mu);
  kthread_t threads[2];
  int threads_started GUARDED_BY(&mu);
} exec_thread_test_args_t;

void* do_nothing(void* arg) { return NULL; }

void* exec_thread_test_thread(void* arg) {
  sched_enable_preemption_for_test();
  exec_thread_test_args_t* args = (exec_thread_test_args_t*)arg;
  kmutex_lock(&args->mu);
  ++args->threads_started;
  scheduler_wake_all(&args->q);
  kmutex_unlock(&args->mu);
  ksleep(20);
  // Try to create a new thread --- it should fail.
  kthread_t thread;
  KEXPECT_EQ(-EINTR, proc_thread_create(&thread, &do_nothing, NULL));
  return NULL;
}

static void exec_thread_test_proc(void* arg) {
  exec_thread_test_args_t* args = (exec_thread_test_args_t*)arg;
  const int kThreads = 2;
  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&args->threads[i],
                                     &exec_thread_test_thread, arg));
    kthread_detach(args->threads[i]);
  }

  // Wait until all the threads are waiting, then exit.
  kmutex_lock(&args->mu);
  while (args->threads_started < kThreads) {
    scheduler_wait_on_locked(&args->q, -1, &args->mu);
  }
  kmutex_unlock(&args->mu);

  // Call exec().  This should block until the threads exit.
  char* const argv[] = {args->bin, NULL};
  char* const envp[] = {NULL};
  int fd = vfs_open("_exec_output", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_EQ(1, vfs_dup2(fd, 1));
  KEXPECT_EQ(2, vfs_dup2(fd, 2));
  do_execve(args->bin, argv, envp, NULL, NULL);
  KTEST_ADD_FAILURE("exec() returned");
  proc_exit(1);
}

static void do_exec(void* arg) {
  exec_thread_test_args_t* args = (exec_thread_test_args_t*)arg;

  char* const argv[] = {args->bin, NULL};
  char* const envp[] = {NULL};
  do_execve(args->bin, argv, envp, NULL, NULL);
  KTEST_ADD_FAILURE("exec() returned");
  proc_exit(1);
}

static ssize_t get_size(const char* fname) {
  apos_stat_t stat;
  stat.st_size = -1;
  KEXPECT_EQ(0, vfs_stat(fname, &stat));
  return stat.st_size;
}

static void exec_thread_test(void) {
  KTEST_BEGIN("exec(): kills all threads test");
  // First, fork a child to run the binary in question to make sure it is warm
  // in the block cache.
  const char* kTestBin = "/bin/ls";
  exec_thread_test_args_t args;
  kstrcpy(args.bin, kTestBin);
  kpid_t pid = proc_fork(&do_exec, &args);
  int status = 100;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));

  // Now run the actual test.
  kstrcpy(args.bin, kTestBin);
  kmutex_init(&args.mu);
  kthread_queue_init(&args.q);

  kmutex_lock(&args.mu);
  args.threads_started = 0;

  pid = proc_fork(&exec_thread_test_proc, &args);
  while (args.threads_started < 2) {
    scheduler_wait_on_locked(&args.q, -1, &args.mu);
  }
  kmutex_unlock(&args.mu);

  // Disable the threads.  In theory this shouldn't be necessary, but things get
  // funny when the signals are sent, and the threads can end up starving each
  // other in tight loops.
  kthread_disable(args.threads[0]);
  kthread_disable(args.threads[1]);

  // Now both threads have been started.  The main thread should not exec yet.
  ksleep(50);
  KEXPECT_EQ(0, proc_waitpid(pid, NULL, WNOHANG));
  KEXPECT_EQ(0, get_size("_exec_output"));

  // Let the first thread finish.  The process still should not exec.
  kthread_enable(args.threads[1]);
  ksleep(50);
  KEXPECT_EQ(0, proc_waitpid(pid, NULL, WNOHANG));
  KEXPECT_EQ(0, get_size("_exec_output"));

  // Let the second thread finish.  The process can exec().
  kthread_enable(args.threads[0]);
  status = 100;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);
  KEXPECT_GT(get_size("_exec_output"), 1);
  KEXPECT_EQ(0, vfs_unlink("_exec_output"));
}

void exec_test(void) {
  KTEST_SUITE_BEGIN("exec() tests");

  const kmode_t orig_umask = proc_umask(0);
  exec_mode_test();
#if ARCH_RUN_USER_TESTS
  exec_thread_test();
#endif
  proc_umask(orig_umask);

  // TODO(aoates): do much more extensive tests, including,
  //  * bad path
  //  * execing a directory
  //  * valid executable
  //  * cleanup function is called
  //  * various bad ELF file tests.
}
