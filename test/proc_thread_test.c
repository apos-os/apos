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

#include "test/ktest.h"

#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"

static bool has_sigtkill(void) {
  return ksigismember(&kthread_current_thread()->assigned_signals,
                      SIGAPOSTKILL);
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
  proc_dispatch_pending_signals(NULL, NULL);
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
}

void proc_thread_test(void) {
  KTEST_SUITE_BEGIN("proc threads tests");
  basic_tests();
}
