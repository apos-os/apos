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

#include <stdint.h>

#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"

// TODO(aoates): other things to test:
//  * multiple threads join()'d onto one thread

static void* thread_func(void* arg) {
  int id = (int)arg;
  KLOG("THREAD STARTED: %d\n", id);
  for (int i = 0; i < 3; ++i) {
    KLOG("THREAD ITER: %d (iter %d)\n", id, i);
    scheduler_yield();
  }
  KLOG("THREAD %d: done\n", id);
  return 0;
}

static void yield_test(void) {
  // Repeatedly yield and make sure we get to the end.
  KTEST_BEGIN("trivial yield test");

  scheduler_yield();
  scheduler_yield();
  scheduler_yield();

  KLOG("  DONE\n");
}

static void basic_test(void) {
  KTEST_BEGIN("basic test");
  kthread_t thread1;
  kthread_t thread2;
  kthread_t thread3;

  KASSERT(kthread_create(&thread1, &thread_func, (void*)1) == 0);
  KASSERT(kthread_create(&thread2, &thread_func, (void*)2) == 0);
  KASSERT(kthread_create(&thread3, &thread_func, (void*)3) == 0);

  scheduler_make_runnable(thread1);
  scheduler_make_runnable(thread2);
  scheduler_make_runnable(thread3);

  kthread_join(thread1);
  kthread_join(thread2);
  kthread_join(thread3);

  KLOG("MAIN THREAD: done\n");
}

static void* kthread_exit_thread_func(void* arg) {
  kthread_exit(arg);
  KASSERT(0);
  return 0;
}

static void kthread_exit_test(void) {
  KTEST_BEGIN("kthread_exit() test");
  kthread_t thread1;

  KASSERT(!kthread_create(&thread1, &kthread_exit_thread_func, (void*)0xabcd));
  scheduler_make_runnable(thread1);
  KEXPECT_EQ(0xabcd, (uint32_t)kthread_join(thread1));
}

static void* kthread_return_thread_func(void* arg) {
  return arg;
}

static void kthread_return_test(void) {
  KTEST_BEGIN("explicit return test");
  kthread_t thread1;

  KASSERT(kthread_create(&thread1, &kthread_return_thread_func, (void*)0xabcd)
          == 0);
  scheduler_make_runnable(thread1);
  KEXPECT_EQ(0xabcd, (uint32_t)kthread_join(thread1));
}

static void* join_test_func(void* arg) {
  kthread_t t = (kthread_t)arg;
  // Yield a few times then join.
  scheduler_yield();
  scheduler_yield();
  scheduler_yield();
  if (t) {
    return (void*)((int)kthread_join(t) + 1);
  } else {
    return 0;
  }
}

#define JOIN_CHAIN_TEST_SIZE 10

// Chain together a bunch of joined threads.
static void join_chain_test(void) {
  KTEST_BEGIN("chained join test");

  kthread_t threads[JOIN_CHAIN_TEST_SIZE];
  for (int i = 0; i < JOIN_CHAIN_TEST_SIZE; i++) {
    kthread_t target = i > 0 ? threads[i-1] : 0;
    int result = kthread_create(&threads[i], &join_test_func, (void*)target);
    KASSERT(result == 0);
    scheduler_make_runnable(threads[i]);
  }

  int out = (int)kthread_join(threads[JOIN_CHAIN_TEST_SIZE-1]);
  KEXPECT_EQ(JOIN_CHAIN_TEST_SIZE - 1, out);
}

// Similar to above, but *create* the next thread in the sequence.
static void* join_test2_func(void* arg) {
  int x = (int)arg;
  if (!x) {
    return 0;
  }
  kthread_t next;
  KASSERT(kthread_create(&next, &join_test2_func, (void*)(x-1)) == 0);
  scheduler_make_runnable(next);
  return (void*)(1 + (int)kthread_join(next));
}

// Chain together a bunch of joined threads.  This time, each thread CREATES the
// next thread in the chain.
static void join_chain_test2(void) {
  KTEST_BEGIN("chained join test #2");

  kthread_t thread;
  int result = kthread_create(&thread, &join_test2_func,
                              (void*)JOIN_CHAIN_TEST_SIZE);
  KASSERT(result == 0);
  scheduler_make_runnable(thread);

  int out = (int)kthread_join(thread);
  KEXPECT_EQ(JOIN_CHAIN_TEST_SIZE, out);
}

static void* noop_func(void* arg) { return 0; }

static void queue_test(void) {
  KTEST_BEGIN("queue operations test");
  kthread_t thread1, thread2, thread3;
  int ret = kthread_create(&thread1, &noop_func, 0x0);
  KASSERT(ret == 0);
  ret = kthread_create(&thread2, &noop_func, 0x0);
  KASSERT(ret == 0);
  ret = kthread_create(&thread3, &noop_func, 0x0);
  KASSERT(ret == 0);

  kthread_queue_t queue;
  kthread_queue_init(&queue);
  KEXPECT_EQ(1, kthread_queue_empty(&queue));
  KEXPECT_EQ(0, (uint32_t)kthread_queue_pop(&queue));

  kthread_queue_push(&queue, thread1);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(&queue, thread1->queue);

  kthread_queue_push(&queue, thread2);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(&queue, thread2->queue);

  kthread_t popped = kthread_queue_pop(&queue);
  KEXPECT_EQ(0x0, (uint32_t)popped->next);
  KEXPECT_EQ(0x0, (uint32_t)popped->prev);
  KEXPECT_EQ((void*)0x0, popped->queue);
  KEXPECT_EQ((uint32_t)thread1, (uint32_t)popped);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));

  popped = kthread_queue_pop(&queue);
  KEXPECT_EQ(0x0, (uint32_t)popped->next);
  KEXPECT_EQ(0x0, (uint32_t)popped->prev);
  KEXPECT_EQ((void*)0x0, popped->queue);
  KEXPECT_EQ((uint32_t)thread2, (uint32_t)popped);
  KEXPECT_EQ(1, kthread_queue_empty(&queue));

  KEXPECT_EQ(0, (uint32_t)kthread_queue_pop(&queue));

  KTEST_BEGIN("kthread_queue_remove(): only element on list");
  kthread_queue_push(&queue, thread1);
  kthread_queue_remove(thread1);
  KEXPECT_EQ(1, kthread_queue_empty(&queue));
  KEXPECT_EQ((void*)0x0, thread1->prev);
  KEXPECT_EQ((void*)0x0, thread1->next);

  KTEST_BEGIN("kthread_queue_remove(): first element of list");
  kthread_queue_push(&queue, thread1);
  kthread_queue_push(&queue, thread2);
  kthread_queue_remove(thread1);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ((void*)0x0, thread1->queue);
  KEXPECT_EQ(thread2, queue.head);
  KEXPECT_EQ(thread2, queue.tail);
  KEXPECT_EQ((void*)0x0, thread1->prev);
  KEXPECT_EQ((void*)0x0, thread1->next);
  KEXPECT_EQ((void*)0x0, thread2->prev);
  KEXPECT_EQ((void*)0x0, thread2->next);
  kthread_queue_pop(&queue);

  KTEST_BEGIN("kthread_queue_remove(): last element of list");
  kthread_queue_push(&queue, thread2);
  kthread_queue_push(&queue, thread1);
  kthread_queue_remove(thread1);
  KEXPECT_EQ((void*)0x0, thread1->queue);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(thread2, queue.head);
  KEXPECT_EQ(thread2, queue.tail);
  KEXPECT_EQ((void*)0x0, thread1->prev);
  KEXPECT_EQ((void*)0x0, thread1->next);
  KEXPECT_EQ((void*)0x0, thread2->prev);
  KEXPECT_EQ((void*)0x0, thread2->next);
  kthread_queue_pop(&queue);

  KTEST_BEGIN("kthread_queue_remove(): middle element of list");
  kthread_queue_push(&queue, thread2);
  kthread_queue_push(&queue, thread1);
  kthread_queue_push(&queue, thread3);
  kthread_queue_remove(thread1);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(thread2, queue.head);
  KEXPECT_EQ(thread3, queue.tail);
  KEXPECT_EQ((void*)0x0, thread2->prev);
  KEXPECT_EQ(thread3, thread2->next);
  KEXPECT_EQ(thread2, thread3->prev);
  KEXPECT_EQ((void*)0x0, thread3->next);
  KEXPECT_EQ((void*)0x0, thread1->prev);
  KEXPECT_EQ((void*)0x0, thread1->next);
  KEXPECT_EQ((void*)0x0, thread1->queue);
  kthread_queue_pop(&queue);
  kthread_queue_pop(&queue);

  // Clean up.
  kthread_detach(thread1);
  kthread_detach(thread2);
  kthread_detach(thread3);
  scheduler_make_runnable(thread1);
  scheduler_make_runnable(thread2);
  scheduler_make_runnable(thread3);
  scheduler_yield();
}

typedef struct {
  uint32_t waiting;
  uint32_t ran;
  kthread_queue_t* queue;
  bool interruptable;
} queue_test_funct_data_t;

// Set the waiting flag, then wait on the given queue, then set the ran flag.
static void* queue_test_func(void* arg) {
  queue_test_funct_data_t* d = (queue_test_funct_data_t*)arg;
  d->waiting = 1;
  int interrupted = 0;
  if (d->interruptable) {
    interrupted = scheduler_wait_on_interruptable(d->queue);
  } else {
    scheduler_wait_on(d->queue);
  }
  d->ran = 1;
  return (void*)interrupted;
}

static void scheduler_wait_on_test(void) {
  KTEST_BEGIN("scheduler_wait_on() test");
  kthread_t thread1, thread2, thread3;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  queue_test_funct_data_t d1 = {0, 0, &queue, false};
  kthread_create(&thread1, &queue_test_func, &d1);
  queue_test_funct_data_t d2 = {0, 0, &queue, false};
  kthread_create(&thread2, &queue_test_func, &d2);
  queue_test_funct_data_t d3 = {0, 0, &queue, false};
  kthread_create(&thread3, &queue_test_func, &d3);

  scheduler_make_runnable(thread1);
  scheduler_make_runnable(thread2);
  scheduler_make_runnable(thread3);

  scheduler_yield();

  KEXPECT_EQ(1, d1.waiting);
  KEXPECT_EQ(0, d1.ran);
  KEXPECT_EQ(1, d2.waiting);
  KEXPECT_EQ(0, d2.ran);
  KEXPECT_EQ(1, d3.waiting);
  KEXPECT_EQ(0, d3.ran);

  scheduler_make_runnable(kthread_queue_pop(&queue));
  scheduler_make_runnable(kthread_queue_pop(&queue));
  scheduler_make_runnable(kthread_queue_pop(&queue));

  scheduler_yield();
  KEXPECT_EQ(1, d1.waiting);
  KEXPECT_EQ(1, d1.ran);
  KEXPECT_EQ(1, d2.waiting);
  KEXPECT_EQ(1, d2.ran);
  KEXPECT_EQ(1, d3.waiting);
  KEXPECT_EQ(1, d3.ran);

  kthread_join(thread1);
  kthread_join(thread2);
  kthread_join(thread3);
}

static void scheduler_wake_test(void) {
  KTEST_BEGIN("scheduler_wake_one() test");
  kthread_t thread1, thread2, thread3;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  queue_test_funct_data_t d1 = {0, 0, &queue, false};
  kthread_create(&thread1, &queue_test_func, &d1);
  queue_test_funct_data_t d2 = {0, 0, &queue, false};
  kthread_create(&thread2, &queue_test_func, &d2);
  queue_test_funct_data_t d3 = {0, 0, &queue, false};
  kthread_create(&thread3, &queue_test_func, &d3);

  scheduler_make_runnable(thread1);
  scheduler_make_runnable(thread2);
  scheduler_make_runnable(thread3);

  scheduler_yield();

  KEXPECT_EQ(1, d1.waiting);
  KEXPECT_EQ(0, d1.ran);
  KEXPECT_EQ(1, d2.waiting);
  KEXPECT_EQ(0, d2.ran);
  KEXPECT_EQ(1, d3.waiting);
  KEXPECT_EQ(0, d3.ran);

  scheduler_wake_one(&queue);
  scheduler_yield();
  scheduler_yield();

  KEXPECT_EQ(1, d1.ran);
  KEXPECT_EQ(0, d2.ran);
  KEXPECT_EQ(0, d3.ran);

  KTEST_BEGIN("scheduler_wake_all() test");
  scheduler_wake_all(&queue);
  scheduler_yield();
  scheduler_yield();

  KEXPECT_EQ(1, d1.ran);
  KEXPECT_EQ(1, d2.ran);
  KEXPECT_EQ(1, d3.ran);

  KTEST_BEGIN("scheduler_wake_one(): empty queue test");
  scheduler_wake_one(&queue);
  scheduler_yield();
  KEXPECT_EQ(1, kthread_queue_empty(&queue));

  KTEST_BEGIN("scheduler_wake_all(): empty queue test");
  scheduler_wake_all(&queue);
  scheduler_yield();
  KEXPECT_EQ(1, kthread_queue_empty(&queue));

  kthread_join(thread1);
  kthread_join(thread2);
  kthread_join(thread3);
}

static void scheduler_interrupt_test(void) {
  KTEST_BEGIN("scheduler_interrupt_thread(): interruptable thread ");
  kthread_t thread1;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(true, thread1->interrupted);
    KEXPECT_EQ((void*)1, kthread_join(thread1));
  }


  KTEST_BEGIN("scheduler_interrupt_thread(): non-interruptable thread ");
  {
    queue_test_funct_data_t d2 = {0, 0, &queue, false};
    kthread_create(&thread1, &queue_test_func, &d2);
    scheduler_make_runnable(thread1);
    while (!d2.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d2.ran; ++i) scheduler_yield();
    KEXPECT_EQ(0, d2.ran);

    scheduler_wake_one(&queue);
    for (int i = 0; i < 5 && !d2.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d2.ran);

    KEXPECT_EQ(false, thread1->interrupted);
    KEXPECT_EQ((void*)0, kthread_join(thread1));
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): pending-on-run-queue thread ");
  {
    queue_test_funct_data_t d3 = {0, 0, &queue, false};
    kthread_create(&thread1, &queue_test_func, &d3);
    scheduler_make_runnable(thread1);

    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d3.waiting; ++i) scheduler_yield();
    KEXPECT_EQ(1, d3.waiting);
    KEXPECT_EQ(0, d3.ran);

    scheduler_wake_one(&queue);
    for (int i = 0; i < 5 && !d3.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d3.ran);

    KEXPECT_EQ(false, thread1->interrupted);
    KEXPECT_EQ((void*)0, kthread_join(thread1));
  }

  KTEST_BEGIN(
      "scheduler_interrupt_thread(): immediate return with pending signals");
  {
    proc_force_signal_on_thread(proc_current(), kthread_current_thread(),
                                SIGUSR1);
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue));
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue));
    KEXPECT_EQ(1, kthread_current_thread()->interrupted);

    proc_suppress_signal(proc_current(), SIGUSR1);
    kthread_current_thread()->interrupted = 0;
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): current thread (running)");
  KEXPECT_EQ((void*)0x0, kthread_current_thread()->queue);

  scheduler_interrupt_thread(kthread_current_thread());
  KEXPECT_EQ((void*)0x0, kthread_current_thread()->queue);
  KEXPECT_EQ(false, kthread_current_thread()->interrupted);

  // TODO(aoates): test a thread that does an interruptable wait followed by a
  // non-interruptable wait; verify that the second wait is uninterruptable, and
  // that the interrupted bit is reset.

  // TODO(aoates): stress/multi-threaded/interrupt test
}

#define STRESS_TEST_ITERS 1000
#define STRESS_TEST_THREADS 1000

static void* stress_test_func(void* arg) {
  KLOG("THREAD %d START\n", (int)arg);
  for (int i = 0; i < STRESS_TEST_ITERS; ++i) {
    scheduler_yield();
  }
  KLOG("THREAD %d DONE\n", (int)arg);
  return arg;
}

// TODO(aoates): make this random.
static void stress_test(void) {
  KTEST_BEGIN("stress test");
  kthread_t threads[STRESS_TEST_THREADS];

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i], &stress_test_func, (void*)i) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    KEXPECT_EQ(i, (int)kthread_join(threads[i]));
  }
}


static kmutex_t kmutex_test_mutex;
static void* kmutex_test_func(void* arg) {
  int* x = (int*)arg;
  for (int i = 0; i < 1000; ++i) {
    kmutex_lock(&kmutex_test_mutex);
    int dummy = *x;
    scheduler_yield();
    dummy++;
    *x = dummy;
    kmutex_unlock(&kmutex_test_mutex);
  }
  return 0;
}

#define KMUTEX_TEST_SIZE 5
static void kmutex_test(void) {
  KTEST_BEGIN("kmutex test");
  kmutex_init(&kmutex_test_mutex);

  kthread_t threads[KMUTEX_TEST_SIZE];
  int out = 0;
  for (int i = 0; i < KMUTEX_TEST_SIZE; ++i) {
    int result = kthread_create(&threads[i], &kmutex_test_func, (void*)(&out));
    KASSERT(result == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < KMUTEX_TEST_SIZE; ++i) {
    kthread_join(threads[i]);
  }

  KEXPECT_EQ(1000 * KMUTEX_TEST_SIZE, out);
}

static void kmutex_auto_lock_test(void) {
  KTEST_BEGIN("kmutex auto lock test");
  kmutex_t m;
  kmutex_init(&m);

  KEXPECT_EQ(0, kmutex_is_locked(&m));
  {
    KEXPECT_EQ(0, kmutex_is_locked(&m));
    KMUTEX_AUTO_LOCK(my_lock, &m);
    KEXPECT_NE(0, kmutex_is_locked(&m));
  }
  KEXPECT_EQ(0, kmutex_is_locked(&m));

  // Verify that it doesn't evaluate side effects more than once.
  KTEST_BEGIN("kmutex auto lock single evaluation");
  {
    int i = 0;
    KMUTEX_AUTO_LOCK(my_lock, &m + i++);
    KEXPECT_EQ(1, i);
  }
}

static void* sleep_func(void* arg) {
  ksleep(1);
  return 0x0;
}

static void ksleep_test(void) {
  const int kNumThreads = 300;

  KTEST_BEGIN("ksleep() stress test");
  kthread_t threads[kNumThreads];

  int threads_created = 0;
  for (int i = 0; i < kNumThreads; ++i) {
    if (kthread_create(&threads[i], &sleep_func, 0x0) == 0) {
      threads_created++;
      scheduler_make_runnable(threads[i]);

      // Spin for a bit to spread the threads out and make it more likely that
      // an interrupt will hit in one of them.
      for (volatile int j = 0; j < 10000; ++j);
    }
  }

  KEXPECT_EQ(kNumThreads, threads_created);

  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
}

// TODO(aoates): add some more involved kmutex tests.

void kthread_test(void) {
  KTEST_SUITE_BEGIN("kthread_test");

  yield_test();
  basic_test();
  kthread_exit_test();
  kthread_return_test();
  join_chain_test();
  join_chain_test2();
  queue_test();
  scheduler_wait_on_test();
  scheduler_wake_test();
  scheduler_interrupt_test();
  stress_test();
  kmutex_test();
  kmutex_auto_lock_test();
  ksleep_test();
}
