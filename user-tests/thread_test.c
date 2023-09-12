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
#include <assert.h>
#include <stdint.h>

#include <apos/sleep.h>
#include <apos/syscall_decls.h>

#include "all_tests.h"
#include "ktest.h"
#include "user-tests/arch.h"

#if ARCH_IS_64_BIT
typedef uint64_t stackelt_t;
#else
typedef uint32_t stackelt_t;
#endif
_Static_assert(sizeof(void*) == sizeof(stackelt_t), "bad stackelt_t");

static void* thread_stack_ptr = 0x0;

void basic_thread_test_tramp_fn(void);
void basic_thread_test_fn(void* arg) {
  thread_stack_ptr = arg;
  apos_thread_exit();
}

static char thread_stack[10000];

static void basic_thread_test(void) {
  KTEST_BEGIN("Basic thread creation test");
  apos_uthread_id_t thread;
  pid_t child = fork();
  if (child == 0) {
    thread_stack_ptr = NULL;
    assert(0 == apos_thread_create(&thread, &thread_stack[9999],
                                   &basic_thread_test_tramp_fn));
    for (int i = 0; i < 10; ++i) {
      sleep_ms(10);
      if (thread_stack_ptr != NULL) break;
    }
    assert(thread_stack_ptr == (void*)((size_t)&thread_stack + 9999));
    exit(0);
  }
  int status;
  waitpid(child, &status, 0);
  KEXPECT_EQ(0, status);
}

// Small wrapper that sets up the stack appropriately.
void thread_test_create_tramp(void);
static int create_thread(apos_uthread_id_t* id, void (*fn)(void*), void* arg) {
  // We leak each thread's stack.  That's fine.
  const int kStackSize = 4 * 8192;
  stackelt_t* stack = malloc(kStackSize);
  stackelt_t* stack_top = &stack[kStackSize / sizeof(stackelt_t) - 1];
  *--stack_top = (stackelt_t)arg;
  *--stack_top = (stackelt_t)fn;
  return apos_thread_create(id, stack_top, &thread_test_create_tramp);
}

static void do_exit_thread(void* x) {
  apos_thread_exit();
}

static void do_proc_exit_thread(void* x) {
  exit((intptr_t)x);
}

static void sleep_and_be_killed(void* x) {
  // Sleep should be interrupted early.
  sleep_ms(10000);
  assert(0 == 1);  // Should be unreachable.
}

static void all_threads_thread_exit(void* x) {
  apos_uthread_id_t A, B;
  KEXPECT_EQ(0, create_thread(&A, do_exit_thread, (void*)0x1234));
  KEXPECT_EQ(0, create_thread(&B, do_exit_thread, (void*)0x1234));
  do_exit_thread((void*)0x1234);
}

static void all_threads_proc_exit(void* x) {
  apos_uthread_id_t A, B;
  KEXPECT_EQ(0, create_thread(&A, do_proc_exit_thread, (void*)1));
  KEXPECT_EQ(0, create_thread(&B, do_proc_exit_thread, (void*)1));
  exit(1);
}

static void main_thread_exits(void* x) {
  apos_uthread_id_t A, B;
  KEXPECT_EQ(0, create_thread(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, create_thread(&B, sleep_and_be_killed, NULL));
  exit(1);
}

// As above, but sleep a bit before exiting to let the other threads run.
static void main_thread_exits2(void* x) {
  apos_uthread_id_t A, B;
  KEXPECT_EQ(0, create_thread(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, create_thread(&B, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, sleep_ms(20));
  exit(1);
}

static void non_main_thread_exits(void* x) {
  apos_uthread_id_t A, B;
  KEXPECT_EQ(0, create_thread(&A, sleep_and_be_killed, NULL));
  KEXPECT_EQ(0, create_thread(&B, do_proc_exit_thread, (void*)1));
  sleep_and_be_killed(NULL);
}

static void more_tests(void) {
  KTEST_BEGIN("threads: one thread, exits with proc_thread_exit()");
  pid_t pid = fork();
  if (pid == 0) {
    apos_thread_exit();
    assert(0 == 1);  // Should be unreachable.
  }
  int status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("threads: three threads, all exit with proc_thread_exit()");
  pid = fork();
  if (pid == 0) {
    all_threads_thread_exit((void*)0x1234);
    assert(0 == 1);  // Should be unreachable.
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(0, status);

  KTEST_BEGIN("threads: three threads, all exit with proc_exit()");
  pid = fork();
  if (pid == 0) {
    all_threads_proc_exit((void*)0x1234);
    assert(0 == 1);  // Should be unreachable.
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("threads: main thread exits with proc_exit()");
  pid = fork();
  if (pid == 0) {
    main_thread_exits(NULL);
    assert(0 == 1);  // Should be unreachable.
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("threads: main thread exits with proc_exit() #2");
  pid = fork();
  if (pid == 0) {
    main_thread_exits2(NULL);
    assert(0 == 1);  // Should be unreachable.
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("threads: non-main thread exits with proc_exit()");
  pid = fork();
  if (pid == 0) {
    non_main_thread_exits(NULL);
    assert(0 == 1);  // Should be unreachable.
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_EQ(1, status);
}

static void invalid_args_tests(void) {
  KTEST_BEGIN("threads: pass NULL for stack");
  apos_uthread_id_t id;
  pid_t pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0, apos_thread_create(&id, NULL, &thread_test_create_tramp));
    apos_thread_exit();
  }
  int status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));

  KTEST_BEGIN("threads: pass unmapped address for stack");
  pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0, apos_thread_create(&id, (void*)INVALID_ADDR,
                                     &thread_test_create_tramp));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));

  KTEST_BEGIN("threads: pass kernel address for stack");
  pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0, apos_thread_create(&id, (void*)0xd0028000,
                                     &thread_test_create_tramp));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));


  KTEST_BEGIN("threads: just-invalid address for stack");
  pid = fork();
  if (pid == 0) {
    void* addr = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(addr != NULL);
    assert(0 == munmap(addr, 4096));
    stackelt_t* stack_top =
        (stackelt_t*)((intptr_t)addr + 4096 + sizeof(stackelt_t));
    *--stack_top = (stackelt_t)all_threads_thread_exit;
    KEXPECT_EQ(0, apos_thread_create(&id, (void*)((stackelt_t)addr + 4096),
                                     &thread_test_create_tramp));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));


  KTEST_BEGIN("threads: read-only address for stack");
  pid = fork();
  if (pid == 0) {
    void* addr = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(addr != NULL);
    KEXPECT_EQ(0, apos_thread_create(&id, (void*)((stackelt_t)addr + 4096),
                                     &thread_test_create_tramp));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));


  KTEST_BEGIN("threads: pass NULL for function");
  pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0, apos_thread_create(&id, &thread_stack[1000], NULL));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));

  KTEST_BEGIN("threads: pass unmapped address for function");
  pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0,
               apos_thread_create(&id, &thread_stack[1000], (void*)INVALID_ADDR));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));

  KTEST_BEGIN("threads: pass kernel address for function");
  pid = fork();
  if (pid == 0) {
    KEXPECT_EQ(0,
               apos_thread_create(&id, &thread_stack[1000], (void*)0xd0028000));
    apos_thread_exit();
  }
  status = -1;
  KEXPECT_EQ(pid, waitpid(pid, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));
}

static void sleep_then_write(void* arg) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTSTP);
  assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));

  sleep_ms(10);
  sleep_ms(10);
  char file[100];
  sprintf(file, "thread%d", (int)(intptr_t)arg);
  int fd = open(file, O_CREAT | O_RDWR, S_IRWXU);
  assert(fd >= 0);
  close(fd);
  apos_thread_exit();
}

static bool file_exists(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    close(fd);
    return true;
  }
  assert(errno == ENOENT);
  return false;
}

static void multi_threaded_stop_test(void) {
  KTEST_BEGIN("threads: SIGSTOP stops all threads");
  pid_t pid = fork();
  if (pid == 0) {
    apos_uthread_id_t ids[3];
    create_thread(&ids[0], &sleep_then_write, (void*)1);
    create_thread(&ids[1], &sleep_then_write, (void*)2);
    create_thread(&ids[2], &sleep_then_write, (void*)3);
    apos_thread_exit();
  }
  sleep_ms(1);
  kill(pid, SIGSTOP);
  sleep_ms(30);
  KEXPECT_FALSE(file_exists("thread1"));
  KEXPECT_FALSE(file_exists("thread2"));
  KEXPECT_FALSE(file_exists("thread3"));
  kill(pid, SIGCONT);
  sleep_ms(30);
  KEXPECT_TRUE(file_exists("thread1"));
  KEXPECT_TRUE(file_exists("thread2"));
  KEXPECT_TRUE(file_exists("thread3"));
  kill(pid, SIGKILL);
  KEXPECT_EQ(0, unlink("thread1"));
  KEXPECT_EQ(0, unlink("thread2"));
  KEXPECT_EQ(0, unlink("thread3"));


  KTEST_BEGIN("threads: SIGTSTP stops all threads (even if masked in some)");
  pid = fork();
  if (pid == 0) {
    apos_uthread_id_t ids[3];
    create_thread(&ids[0], &sleep_then_write, (void*)1);
    create_thread(&ids[1], &sleep_then_write, (void*)2);
    create_thread(&ids[2], &sleep_then_write, (void*)3);
    sleep(10);  // This thread will handle the SIGTSTP.
    apos_thread_exit();
  }
  sleep_ms(1);
  kill(pid, SIGTSTP);
  sleep_ms(30);
  KEXPECT_FALSE(file_exists("thread1"));
  KEXPECT_FALSE(file_exists("thread2"));
  KEXPECT_FALSE(file_exists("thread3"));
  kill(pid, SIGCONT);
  sleep_ms(30);
  KEXPECT_TRUE(file_exists("thread1"));
  KEXPECT_TRUE(file_exists("thread2"));
  KEXPECT_TRUE(file_exists("thread3"));
  kill(pid, SIGKILL);
  KEXPECT_EQ(0, unlink("thread1"));
  KEXPECT_EQ(0, unlink("thread2"));
  KEXPECT_EQ(0, unlink("thread3"));


  KTEST_BEGIN("threads: SIGTSTP masked in all threads");
  pid = fork();
  KEXPECT_FALSE(file_exists("thread1"));
  if (pid == 0) {
    apos_uthread_id_t ids[3];
    create_thread(&ids[0], &sleep_then_write, (void*)1);
    create_thread(&ids[1], &sleep_then_write, (void*)2);
    create_thread(&ids[2], &sleep_then_write, (void*)3);
    apos_thread_exit();
  }
  sleep_ms(1);
  sleep_ms(1);
  kill(pid, SIGTSTP);
  sleep_ms(30);
  KEXPECT_TRUE(file_exists("thread1"));
  KEXPECT_TRUE(file_exists("thread2"));
  KEXPECT_TRUE(file_exists("thread3"));
  kill(pid, SIGKILL);
  KEXPECT_EQ(0, unlink("thread1"));
  KEXPECT_EQ(0, unlink("thread2"));
  KEXPECT_EQ(0, unlink("thread3"));
}

typedef struct {
  sigset_t set;
  int result;
  int sig;
  bool thread_done;
} threadtest_data_t;

static void thread_sigwait(void* arg) {
  threadtest_data_t* data = (threadtest_data_t*)arg;
  assert(0 == sigprocmask(SIG_BLOCK, &data->set, NULL));
  data->result = sigwait(&data->set, &data->sig);
  data->thread_done = true;
}

static int count_done(const threadtest_data_t* data, int n) {
  int count = 0;
  for (int i = 0; i < n; ++i) {
    if (data[i].thread_done) count++;
  }
  return count;
}

static void basic_thread_signal_test(void) {
  KTEST_BEGIN("threads: signals are only delivered to one thread");
  sigset_t set, orig_set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGHUP);
  sigprocmask(SIG_BLOCK, &set, &orig_set);

  apos_uthread_id_t threads[3];
  threadtest_data_t data[3];
  for (int i = 0; i < 3; ++i) {
    data[i].set = set;
    data[i].sig = -1;
    data[i].result = -1;
    data[i].thread_done = false;
    KEXPECT_EQ(0, create_thread(&threads[i], &thread_sigwait, &data[i]));
  }
  sleep_ms(10);
  KEXPECT_EQ(0, count_done(data, 3));

  KEXPECT_EQ(0, kill(getpid(), SIGUSR1));
  sleep_ms(10);
  KEXPECT_EQ(1, count_done(data, 3));
  int sigusr1_thread = 0;
  for (int i = 0; i < 3; ++i) {
    if (data[i].thread_done) {
      KEXPECT_EQ(0, data[i].result);
      KEXPECT_EQ(SIGUSR1, data[i].sig);
      sigusr1_thread = i;
    }
  }

  KEXPECT_EQ(0, kill(getpid(), SIGUSR2));
  sleep_ms(10);
  KEXPECT_EQ(2, count_done(data, 3));
  int sigusr2_thread = 0;
  for (int i = 0; i < 3; ++i) {
    if (data[i].thread_done && i != sigusr1_thread) {
      KEXPECT_EQ(0, data[i].result);
      KEXPECT_EQ(SIGUSR2, data[i].sig);
      sigusr2_thread = i;
    }
  }

  KEXPECT_EQ(0, kill(getpid(), SIGHUP));
  sleep_ms(10);
  KEXPECT_EQ(3, count_done(data, 3));
  for (int i = 0; i < 3; ++i) {
    if (data[i].thread_done && i != sigusr1_thread && i != sigusr2_thread) {
      KEXPECT_EQ(0, data[i].result);
      KEXPECT_EQ(SIGHUP, data[i].sig);
    }
  }

  KEXPECT_EQ(0, sigprocmask(SIG_SETMASK, &orig_set, NULL));
}

static void get_signal(void* arg) {
  *(int*)arg = 0;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  assert(0 == sigprocmask(SIG_SETMASK, &set, NULL));

  sigdelset(&set, SIGUSR2);
  int sig;
  assert(0 == sigwait(&set, &sig));
  assert(sig == SIGUSR1);
  *(int*)arg = 1;

  sigdelset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  assert(0 == sigwait(&set, &sig));
  assert(sig == SIGUSR2);
  *(int*)arg = 2;
}

static void send_signal_to_thread_test(void) {
  KTEST_BEGIN("apos_thread_kill(): send SIGNULL checks perms");
  apos_uthread_id_t ids[3];
  int status[3];
  for (int i = 0; i < 3; ++i) {
    status[i] = -1;
    KEXPECT_EQ(0, create_thread(&ids[i], &get_signal, &status[i]));
  }

  KEXPECT_EQ(0, apos_thread_kill(&ids[0], 0));

  KTEST_BEGIN("apos_thread_kill(): sending invalid signals");
  KEXPECT_ERRNO(EPERM, apos_thread_kill(&ids[0], 29 /* SIGAPOSTKILL */));
  KEXPECT_ERRNO(EINVAL, apos_thread_kill(&ids[0], 100));
  KEXPECT_ERRNO(EINVAL, apos_thread_kill(&ids[0], -1));
  KEXPECT_ERRNO(EINVAL, apos_thread_kill(&ids[0], APOS_SIGMAX + 1));
  KEXPECT_ERRNO(EINVAL, apos_thread_kill(&ids[0], APOS_SIGMIN - 2));

  KTEST_BEGIN("apos_thread_kill(): invalid IDs");
  apos_uthread_id_t bad_id;
  bad_id._id = -1;
  KEXPECT_ERRNO(ESRCH, apos_thread_kill(&bad_id, 0));
  KEXPECT_ERRNO(ESRCH, apos_thread_kill(&bad_id, SIGINT));
  bad_id._id = 1;
  KEXPECT_ERRNO(ESRCH, apos_thread_kill(&bad_id, 0));
  bad_id._id = ids[2]._id + 1;
  KEXPECT_ERRNO(ESRCH, apos_thread_kill(&bad_id, 0));
  bad_id._id = 10000;  // In theory this could actually be one of the above IDs
  KEXPECT_ERRNO(ESRCH, apos_thread_kill(&bad_id, 0));
  KEXPECT_SIGNAL(SIGSEGV, apos_thread_kill(NULL, 0));
  KEXPECT_SIGNAL(SIGSEGV,
                 apos_thread_kill((const apos_uthread_id_t*)INVALID_ADDR, 0));

  // Despite all the above tests, the threads should not have progressed.
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(0, status[0]);
  KEXPECT_EQ(0, status[1]);
  KEXPECT_EQ(0, status[2]);

  KTEST_BEGIN("apos_thread_kill(): send to particular thread");
  KEXPECT_EQ(0, apos_thread_kill(&ids[1], SIGUSR2));
  // It was masked, none of them should have woken up.
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(0, status[0]);
  KEXPECT_EQ(0, status[1]);
  KEXPECT_EQ(0, status[2]);

  KEXPECT_EQ(0, apos_thread_kill(&ids[2], SIGUSR1));
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(0, status[0]);
  KEXPECT_EQ(0, status[1]);
  KEXPECT_EQ(1, status[2]);

  KEXPECT_EQ(0, apos_thread_kill(&ids[1], SIGUSR1));
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(0, status[0]);
  KEXPECT_EQ(2, status[1]);
  KEXPECT_EQ(1, status[2]);

  KEXPECT_EQ(0, apos_thread_kill(&ids[0], SIGUSR1));
  KEXPECT_EQ(0, apos_thread_kill(&ids[2], SIGUSR2));
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(1, status[0]);
  KEXPECT_EQ(2, status[1]);
  KEXPECT_EQ(2, status[2]);

  KEXPECT_EQ(0, apos_thread_kill(&ids[0], SIGUSR2));
  for (int i = 0; i < 3; ++i) sleep_ms(1);
  KEXPECT_EQ(2, status[0]);
}

static void send_signal_to_thread(void* arg) {
  apos_uthread_id_t* id = (apos_uthread_id_t*)arg;
  KEXPECT_EQ(0, apos_thread_kill(id, SIGUSR1));
  KEXPECT_EQ(0, apos_thread_self(id));
}

static void self_test(void) {
  KTEST_BEGIN("apos_thread_self(): basic test");
  sigset_t set, old_set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  KEXPECT_EQ(0, sigprocmask(SIG_BLOCK, &set, &old_set));

  apos_uthread_id_t me, other;
  KEXPECT_EQ(0, apos_thread_self(&me));
  KEXPECT_EQ(0, create_thread(&other, &send_signal_to_thread, &me));
  KEXPECT_NE(0, memcmp(&me, &other, sizeof(apos_uthread_id_t)));
  KEXPECT_NE(me._id, other._id);

  int sig;
  KEXPECT_EQ(0, sigwait(&set, &sig));
  KEXPECT_EQ(SIGUSR1, sig);
  sleep_ms(10);

  // The other thread should have overwritten `me` with its ID.
  KEXPECT_EQ(0, memcmp(&me, &other, sizeof(apos_uthread_id_t)));

  KEXPECT_EQ(0, sigprocmask(SIG_SETMASK, &old_set, NULL));

  KTEST_BEGIN("apos_thread_self(): invalid arguments");
  KEXPECT_SIGNAL(SIGSEGV, apos_thread_self(NULL));
  KEXPECT_SIGNAL(SIGSEGV, apos_thread_self((apos_uthread_id_t*)INVALID_ADDR));
}

void thread_test(void) {
  KTEST_SUITE_BEGIN("thread tests");

  basic_thread_test();
  more_tests();
  invalid_args_tests();
  multi_threaded_stop_test();

  basic_thread_signal_test();
  send_signal_to_thread_test();
  self_test();

  // TODO(aoates): other interesting tests:
  //  - signal masks and delivery
}
