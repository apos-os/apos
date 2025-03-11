// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include "proc/notification.h"
#include "test/ktest.h"

#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "vfs/pipe.h"
#include "vfs/vfs.h"

static bool has_sigtkill(void) {
  kthread_t thread = kthread_current_thread();
  kthread_lock_proc_spin(thread);
  bool result = ksigismember(&thread->assigned_signals, SIGAPOSTKILL);
  kthread_unlock_proc_spin(thread);
  return result;
}

static void* do_exit_thread(void* x) {
  proc_thread_exit(x);
}

static void* do_proc_exit_thread(void* x) {
  proc_exit((intptr_t)x);
}

static void* sleep_and_be_killed(void* x) {
  // Sleep should be interrupted early.
  KEXPECT_GE(ksleep(10000), 9000);
  KEXPECT_EQ(true, has_sigtkill());
  kspin_lock(&proc_current()->spin_mu);
  KEXPECT_EQ(DISPATCH_NONE, proc_dispatch_pending_signals(NULL, NULL));
  kspin_unlock(&proc_current()->spin_mu);
  KEXPECT_EQ(false, true);  // Should be unreachable.
  return 0x0;
}

static void one_thread_exit_test(void* x) {
  proc_thread_exit(x);
}

static void all_threads_thread_exit(void* x) {
  kthread_t A, B;
  KEXPECT_EQ(0, proc_thread_create(&A, do_exit_thread, (void*)0x1234));
  KEXPECT_EQ(0, proc_thread_create(&B, do_exit_thread, (void*)0x1234));
  kthread_detach(A);
  kthread_detach(B);
  do_exit_thread((void*)0x1234);
}

static void all_threads_proc_exit(void* x) {
  kthread_t A, B;
  KEXPECT_EQ(0, proc_thread_create(&A, do_proc_exit_thread, (void*)1));
  KEXPECT_EQ(0, proc_thread_create(&B, do_proc_exit_thread, (void*)1));
  kthread_detach(A);
  kthread_detach(B);
  proc_exit(1);
}

static void main_thread_exits(void* x) {
  kthread_t A, B;
  KEXPECT_EQ(0, proc_thread_create(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, proc_thread_create(&B, sleep_and_be_killed, NULL));
  kthread_detach(A);
  kthread_detach(B);
  proc_exit(1);
}

// As above, but sleep a bit before exiting to let the other threads run.
static void main_thread_exits2(void* x) {
  kthread_t A, B;
  KEXPECT_EQ(0, proc_thread_create(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, proc_thread_create(&B, sleep_and_be_killed, NULL));
  kthread_detach(A);
  kthread_detach(B);
  KEXPECT_EQ(0, ksleep(20));
  proc_exit(1);
}

static void non_main_thread_exits(void* x) {
  kthread_t A, B;
  KEXPECT_EQ(0, proc_thread_create(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, proc_thread_create(&B, do_proc_exit_thread, (void*)1));
  kthread_detach(A);
  kthread_detach(B);
  sleep_and_be_killed(NULL);
}

static void* just_return(void* x) { return x; }

// Tests that the trampoline passes the return value to kthread_exit if the
// thread function returns.
static void trampoline_exits(void* x) {
  kthread_t A;
  KEXPECT_EQ(0, proc_thread_create(&A, just_return, (void*)0x1234));
  KEXPECT_EQ((void*)0x1234, kthread_join(A));
}

static void* sleep_then_return(void* x) {
  ksleep(10);
  ksleep(10);
  return x;
}

// Tests that the trampoline uses proc_thread_exit() rather than kthread_exit()
// if the thread function returns.
static void trampoline_exits2(void* x) {
  kthread_t A;
  KEXPECT_EQ(0, proc_thread_create(&A, sleep_then_return, (void*)0x1234));
  kthread_detach(A);
  proc_thread_exit(NULL);  // Let the other thread exit the process..
}

// Simulates a thread creation call that happens after or simultaneously with
// another thread calling proc_exit().  This can't currently happen (because the
// kernel is single-threaded and non-preemptible), but could in the future.
static void* sleep_then_create_thread(void* x) {
  ksleep(10);
  KEXPECT_EQ(true, has_sigtkill());
  kthread_t B;
  // This new thread probably shouldn't run.  If it _does_ run, it should be
  // immediately killed.
  int result = proc_thread_create(&B, sleep_and_be_killed, (void*)0x1234);
  if (result == 0) {
    kthread_detach(B);
  } else {
    KEXPECT_EQ(-EINTR, result);
  }
  proc_thread_exit(NULL);
}

static void new_thread_after_exit(void* x) {
  kthread_t A;
  KEXPECT_EQ(0, proc_thread_create(&A, sleep_then_create_thread, NULL));
  kthread_detach(A);
  proc_exit(0);
}

static void basic_tests(void) {
  KTEST_BEGIN("proc threads: one thread, exits with proc_thread_exit()");
  kpid_t pid = proc_fork(&one_thread_exit_test, (void*)0x1234);
  int status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("proc threads: three threads, all exit with proc_thread_exit()");
  pid = proc_fork(&all_threads_thread_exit, (void*)0x1234);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("proc threads: three threads, all exit with proc_exit()");
  pid = proc_fork(&all_threads_proc_exit, (void*)0x1234);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("proc threads: main thread exits with proc_exit()");
  pid = proc_fork(&main_thread_exits, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("proc threads: main thread exits with proc_exit() #2");
  pid = proc_fork(&main_thread_exits2, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("proc threads: non-main thread exits with proc_exit()");
  pid = proc_fork(&non_main_thread_exits, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("proc threads: trampoline exits with return value");
  pid = proc_fork(&trampoline_exits, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("proc threads: trampoline exits process");
  pid = proc_fork(&trampoline_exits2, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("proc threads: thread created during exit");
  pid = proc_fork(&new_thread_after_exit, NULL);
  status = -1;
  KEXPECT_EQ(pid, proc_waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);
}

static void do_nothing(void* args) {
  proc_exit(0);
}

typedef struct {
  notification_t t1_running;
  notification_t t1_finish;
} exit_yield_args_t;

static void exit_yield_thread(void* arg) {
  exit_yield_args_t* args = (exit_yield_args_t*)arg;
  // Fork again (not necessary, but ensure there's a child that has to be
  // reparented to the root process).
  kpid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_GE(child, 0);

  // Open some file descriptors to do more work in process exit.
  int fd[2];
  KEXPECT_EQ(0, vfs_pipe(fd));
  KEXPECT_EQ(25, vfs_dup2(fd[0], 25));

  ntfn_notify(&args->t1_running);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args->t1_finish, 1000));
  proc_exit(0);
  die("unreachable");
}

static void exit_yield_test(void) {
  KTEST_BEGIN("proc threads: thread yields during process exit");
  // This test is pretty white-boxy, but is the easiest way to test this issue.
  exit_yield_args_t args;
  ntfn_init(&args.t1_running);
  ntfn_init(&args.t1_finish);
  kpid_t child = proc_fork(&exit_yield_thread, &args);
  KEXPECT_GE(child, 0);

  // Wait for the thread to be running.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.t1_running, 1000));

  // Now lock the root thread's mutex (as a somewhat arbitrary operation that
  // will cause the process thread to block while it is exiting).
  process_t* root = proc_get(0);
  pmutex_lock(&root->mu);
  // Let the process thread exit.
  ntfn_notify(&args.t1_finish);
  ksleep(20);
  // The exiting thread should be blocked waiting for the root process lock.
  // Unlock it, then wait for it to exit.
  pmutex_unlock(&root->mu);
  int status = 1;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_EQ(0, status);
}

void proc_thread_test(void) {
  KTEST_SUITE_BEGIN("proc threads tests");
  basic_tests();
  exit_yield_test();
}
