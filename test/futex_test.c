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
#include "proc/futex.h"

#include "common/errno.h"
#include "dev/timer.h"
#include "memory/mmap.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "vfs/vfs.h"
#include "test/ktest.h"

typedef struct {
  uint32_t* addr;
  uint32_t val;
  int result;
  bool started;
  bool done;
} futex_test_args;

static void* futex_wait_thread(void* x) {
  futex_test_args* args = (futex_test_args*)x;
  args->started = true;
  args->result = futex_wait(args->addr, args->val, NULL);
  args->done = true;
  return NULL;
}

static void wait_wake_tests(void) {
  KTEST_BEGIN("futex_wake(): possibly uninitialized test");
  void *map1, *map2;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, PROT_ALL, KMAP_SHARED | KMAP_ANONYMOUS,
                        -1, 0, &map1));
  *(uint32_t*)map1 = 0;
  KEXPECT_EQ(0, futex_wake(map1, 10));
  KEXPECT_EQ(0, do_munmap(map1, PAGE_SIZE));

  KTEST_BEGIN("futex_op(): invalid operation");
  KEXPECT_EQ(-EINVAL, futex_op(NULL, 123, 0, NULL, NULL, 0));
  KEXPECT_EQ(-EINVAL, futex_op(NULL, -123, 0, NULL, NULL, 0));


  KTEST_BEGIN("futex_wait(): bad address");
  KEXPECT_EQ(-EFAULT, futex_wait((uint32_t*)0x1234, 0, NULL));
  KEXPECT_EQ(-EFAULT, futex_wait((uint32_t*)&map1, 0, NULL));  // Ptr on stack.


  KTEST_BEGIN("futex_wake(): bad address");
  KEXPECT_EQ(-EFAULT, futex_wake((uint32_t*)0x1234, 1));
  KEXPECT_EQ(-EFAULT, futex_wake((uint32_t*)&map1, 1));  // Ptr on stack.


  KTEST_BEGIN("futex_wait()/futex_wake(): unreadable address");
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, PROT_ALL,
                        KMAP_SHARED | KMAP_ANONYMOUS | KMAP_KERNEL_ONLY, -1, 0,
                        &map1));
  *(uint32_t*)map1 = 0;
  KEXPECT_EQ(-EFAULT, futex_wait((uint32_t*)map1, 0, NULL));
  KEXPECT_EQ(-EFAULT, futex_wait((uint32_t*)map1, 1, NULL));
  KEXPECT_EQ(-EFAULT, futex_wake((uint32_t*)map1, 1));
  KEXPECT_EQ(0, do_munmap(map1, PAGE_SIZE));


  KTEST_BEGIN("futex_wait(): basic test");
  int fd = vfs_open("_futex_test", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, PAGE_SIZE));
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, PROT_ALL, KMAP_SHARED, fd, 0, &map1));
  KEXPECT_EQ(
      0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_READ, KMAP_SHARED, fd, 0, &map2));
  uint32_t* ptr1 = (uint32_t*)map1 + 10;
  uint32_t* ptr2 = (uint32_t*)map2 + 10;

  // The pages aren't mapped yet.
  KEXPECT_EQ(-EFAULT, futex_wait(ptr1, 0, NULL));
  KEXPECT_EQ(-EFAULT, futex_wait(ptr2, 0, NULL));
  KEXPECT_EQ(-EFAULT, futex_wake(ptr1, INT_MAX));
  KEXPECT_EQ(-EFAULT, futex_wake(ptr2, INT_MAX));

  *ptr1 = 0;
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr1, 1, NULL));  // 1 != 0.
  KEXPECT_EQ(-EFAULT, futex_wait(ptr2, 0, NULL));  // Still unmapped.
  KEXPECT_EQ(0, futex_wake(ptr1, INT_MAX));
  KEXPECT_EQ(-EFAULT, futex_wake(ptr2, INT_MAX));

  futex_test_args args;
  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 0;
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));

  while (!args.started) ksleep(1);
  KEXPECT_FALSE(args.done);
  KEXPECT_EQ(0, futex_wake(ptr1, 0));
  ksleep(10);
  KEXPECT_FALSE(args.done);
  KEXPECT_EQ(1, futex_wake(ptr1, 10));
  KEXPECT_EQ(0, futex_wake(ptr1, 10));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(0, args.result);


  KTEST_BEGIN("futex_wait(): different virtual addresses");
  *ptr1 = 123;
  KEXPECT_EQ(123, *ptr2);

  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 123;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));

  while (!args.started) ksleep(1);
  KEXPECT_EQ(1, futex_wake(ptr2, 1));  // Wake ptr2 rather than ptr1.
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(0, args.result);


  KTEST_BEGIN("futex_wait(): value isn't equal");
  *ptr1 = 123;
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr1, 0, NULL));
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr1, 1, NULL));
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr2, 0, NULL));
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr2, 1, NULL));


  KTEST_BEGIN("futex_wait(): timeout");
  struct apos_timespec timeout;
  timeout.tv_sec = 0;
  timeout.tv_nsec = 50 * 1000000;
  apos_ms_t start = get_time_ms();
  *ptr1 = 123;
  KEXPECT_EQ(-ETIMEDOUT, futex_wait(ptr1, 123, &timeout));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 50);
  KEXPECT_LE(end - start, 1000);


  KTEST_BEGIN("futex_wait(): multiple waiters");
  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 123;
  futex_test_args args2 = args;
  args2.addr = ptr2;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));
  kthread_t thread2;
  KEXPECT_EQ(0, proc_thread_create(&thread2, &futex_wait_thread, &args2));

  while (!args.started) ksleep(1);
  while (!args2.started) ksleep(1);
  KEXPECT_FALSE(args.done);
  KEXPECT_FALSE(args2.done);

  KEXPECT_EQ(2, futex_wake(ptr1, INT_MAX));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(NULL, kthread_join(thread2));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(0, args.result);
  KEXPECT_TRUE(args2.done);
  KEXPECT_EQ(0, args2.result);


  KTEST_BEGIN("futex_wake(): only wakes val waiters");
  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 123;
  args2 = args;
  futex_test_args args3 = args;
  args2.addr = ptr2;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));
  KEXPECT_EQ(0, proc_thread_create(&thread2, &futex_wait_thread, &args2));

  while (!args.started) ksleep(1);
  while (!args2.started) ksleep(1);
  KEXPECT_FALSE(args.done);
  KEXPECT_FALSE(args2.done);

  KEXPECT_EQ(1, futex_wake(ptr1, 1));
  ksleep(50);
  KEXPECT_TRUE(args.done || args2.done);  // One should have finished...
  KEXPECT_FALSE(args.done && args2.done);  // ...but not both.

  // For kicks, do a failed wait operation now while things are waiting.
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr1, 5, NULL));
  KEXPECT_EQ(-EAGAIN, futex_wait(ptr1, 50, NULL));

  // Create a third waiter.
  kthread_t thread3;
  KEXPECT_EQ(0, proc_thread_create(&thread3, &futex_wait_thread, &args3));

  while (!args3.started) ksleep(1);
  KEXPECT_EQ(1, futex_wake(ptr1, 1));
  ksleep(50);
  KEXPECT_EQ(2, args.done + args2.done + args3.done);

  KEXPECT_EQ(1, futex_wake(ptr1, 1));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(NULL, kthread_join(thread2));
  KEXPECT_EQ(NULL, kthread_join(thread3));
  KEXPECT_EQ(0, futex_wake(ptr1, 1));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(0, args.result);
  KEXPECT_TRUE(args2.done);
  KEXPECT_EQ(0, args2.result);
  KEXPECT_TRUE(args3.done);
  KEXPECT_EQ(0, args3.result);


  KTEST_BEGIN("futex_wait(): woken up by signal");
  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 123;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));

  while (!args.started) ksleep(1);
  KEXPECT_FALSE(args.done);

  proc_force_signal_on_thread(proc_current(), thread, SIGUSR1);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(-EINTR, args.result);


  KTEST_BEGIN("futex_op(): APOS_FUTEX_WAIT and APOS_FUTEX_WAKE");
  *ptr1 = 123;
  KEXPECT_EQ(-EAGAIN, futex_op(ptr1, APOS_FUTEX_WAIT, 0, NULL, NULL, 0));
  KEXPECT_EQ(-EAGAIN, futex_op(ptr1, APOS_FUTEX_WAIT, 1, NULL, NULL, 0));
  timeout.tv_nsec = 1;
  timeout.tv_sec = 0;
  KEXPECT_EQ(-ETIMEDOUT,
             futex_op(ptr1, APOS_FUTEX_WAIT, 123, &timeout, NULL, 0));

  args.addr = ptr1;
  args.started = args.done = false;
  args.val = 123;
  KEXPECT_EQ(0, proc_thread_create(&thread, &futex_wait_thread, &args));

  while (!args.started) ksleep(1);
  KEXPECT_EQ(1, futex_op(ptr2, APOS_FUTEX_WAKE, 10, NULL, NULL, 0));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_TRUE(args.done);
  KEXPECT_EQ(0, args.result);

  // Cleanup
  KEXPECT_EQ(0, do_munmap(map1, PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(map2, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_futex_test"));
}

void futex_test(void) {
  KTEST_SUITE_BEGIN("futex tests");

  wait_wake_tests();
}
