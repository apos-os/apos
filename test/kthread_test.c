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
#include "common/refcount.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/defint.h"
#include "proc/kthread-internal.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/spinlock.h"
#include "test/ktest.h"
#include "test/test_params.h"

// Enable this to run a test that catches a deadlock (and panics the kernel).
#define RUN_DEADLOCK_DETECTION_FALIURE_TEST 0

// TODO(aoates): other things to test:
//  * multiple threads join()'d onto one thread

static void* thread_func(void* arg) {
  int id = (intptr_t)arg;
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
  KEXPECT_EQ(0xabcd, (intptr_t)kthread_join(thread1));
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
  KEXPECT_EQ(0xabcd, (intptr_t)kthread_join(thread1));
}

static void* join_test_func(void* arg) {
  kthread_t t = (kthread_t)arg;
  // Yield a few times then join.
  scheduler_yield();
  scheduler_yield();
  scheduler_yield();
  if (t) {
    return (void*)((intptr_t)kthread_join(t) + 1);
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

  int out = (intptr_t)kthread_join(threads[JOIN_CHAIN_TEST_SIZE-1]);
  KEXPECT_EQ(JOIN_CHAIN_TEST_SIZE - 1, out);
}

// Similar to above, but *create* the next thread in the sequence.
static void* join_test2_func(void* arg) {
  intptr_t x = (intptr_t)arg;
  if (!x) {
    return 0;
  }
  kthread_t next;
  KASSERT(kthread_create(&next, &join_test2_func, (void*)(x-1)) == 0);
  scheduler_make_runnable(next);
  return (void*)(1 + (intptr_t)kthread_join(next));
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

  int out = (intptr_t)kthread_join(thread);
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
  KEXPECT_EQ(NULL, kthread_queue_pop(&queue));

  kthread_queue_push(&queue, thread1);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(&queue, thread1->queue);

  kthread_queue_push(&queue, thread2);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));
  KEXPECT_EQ(&queue, thread2->queue);

  kthread_t popped = kthread_queue_pop(&queue);
  KEXPECT_EQ(NULL, popped->next);
  KEXPECT_EQ(NULL, popped->prev);
  KEXPECT_EQ(NULL, popped->queue);
  KEXPECT_EQ(thread1, popped);
  KEXPECT_EQ(0, kthread_queue_empty(&queue));

  popped = kthread_queue_pop(&queue);
  KEXPECT_EQ(NULL, popped->next);
  KEXPECT_EQ(NULL, popped->prev);
  KEXPECT_EQ(NULL, popped->queue);
  KEXPECT_EQ(thread2, popped);
  KEXPECT_EQ(1, kthread_queue_empty(&queue));

  KEXPECT_EQ(NULL, kthread_queue_pop(&queue));

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
  bool waiting;
  bool ran;
  kthread_queue_t* queue;
  bool interruptable;
  long timeout;
} queue_test_funct_data_t;

// Set the waiting flag, then wait on the given queue, then set the ran flag.
static void* queue_test_func(void* arg) {
  queue_test_funct_data_t* d = (queue_test_funct_data_t*)arg;
  d->waiting = 1;
  intptr_t wait_result = 0;
  if (d->interruptable) {
    wait_result = scheduler_wait_on_interruptable(d->queue, d->timeout);
  } else {
    scheduler_wait_on(d->queue);
  }
  d->ran = 1;
  return (void*)wait_result;
}

static void scheduler_wait_on_test(void) {
  KTEST_BEGIN("scheduler_wait_on() test");
  kthread_t thread1, thread2, thread3;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  queue_test_funct_data_t d1 = {0, 0, &queue, false, -1};
  kthread_create(&thread1, &queue_test_func, &d1);
  queue_test_funct_data_t d2 = {0, 0, &queue, false, -1};
  kthread_create(&thread2, &queue_test_func, &d2);
  queue_test_funct_data_t d3 = {0, 0, &queue, false, -1};
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

  queue_test_funct_data_t d1 = {0, 0, &queue, false, -1};
  kthread_create(&thread1, &queue_test_func, &d1);
  queue_test_funct_data_t d2 = {0, 0, &queue, false, -1};
  kthread_create(&thread2, &queue_test_func, &d2);
  queue_test_funct_data_t d3 = {0, 0, &queue, false, -1};
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

typedef struct {
  kspinlock_t mu;
  kthread_queue_t q;
  notification_t done;
} race_wait_args_t;

static void* race_wait_test(void* arg) {
  race_wait_args_t* args = (race_wait_args_t*)arg;
  for (int i = 0; i < 1000 * CONCURRENCY_TEST_ITERS_MULT; ++i) {
    kspin_lock(&args->mu);
    scheduler_wait_on_splocked(&args->q, 1, &args->mu);
    kspin_unlock(&args->mu);
  }
  ntfn_notify(&args->done);
  return NULL;
}

static void scheduler_wake_race_test(void) {
  KTEST_BEGIN("scheduler_wake_one() race test");
  kthread_t thread1;

  race_wait_args_t args;
  kthread_queue_init(&args.q);
  ntfn_init(&args.done);
  args.mu = KSPINLOCK_NORMAL_INIT;

  KEXPECT_EQ(0, kthread_create(&thread1, &race_wait_test, &args));
  scheduler_make_runnable(thread1);

  sched_enable_preemption_for_test();
  while (!ntfn_has_been_notified(&args.done)) {
    kspin_lock(&args.mu);
    if (kthread_queue_empty(&args.q)) {
      kspin_unlock(&args.mu);
      scheduler_yield();
      kspin_lock(&args.mu);
    }
    scheduler_wake_one(&args.q);
    kspin_unlock(&args.mu);
  }
  sched_disable_preemption();

  kthread_join(thread1);
}

static void scheduler_wake_all_race_test(void) {
  KTEST_BEGIN("scheduler_wake_all() race test");
  kthread_t thread1;

  race_wait_args_t args;
  kthread_queue_init(&args.q);
  ntfn_init(&args.done);
  args.mu = KSPINLOCK_NORMAL_INIT;

  KEXPECT_EQ(0, kthread_create(&thread1, &race_wait_test, &args));
  scheduler_make_runnable(thread1);

  sched_enable_preemption_for_test();
  while (!ntfn_has_been_notified(&args.done)) {
    kspin_lock(&args.mu);
    if (kthread_queue_empty(&args.q)) {
      kspin_unlock(&args.mu);
      scheduler_yield();
      kspin_lock(&args.mu);
    }
    scheduler_wake_all(&args.q);
    kspin_unlock(&args.mu);
  }
  sched_disable_preemption();

  kthread_join(thread1);
}

static void scheduler_interrupt_test(void) {
  KTEST_BEGIN("scheduler_interrupt_thread(): interruptable thread ");
  kthread_t thread1;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, -1};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(SWAIT_INTERRUPTED, thread1->wait_status);
    KEXPECT_EQ((void*)1, kthread_join(thread1));
  }


  KTEST_BEGIN("scheduler_interrupt_thread(): non-interruptable thread ");
  {
    queue_test_funct_data_t d2 = {0, 0, &queue, false, -1};
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

    KEXPECT_EQ(SWAIT_DONE, thread1->wait_status);
    KEXPECT_EQ((void*)0, kthread_join(thread1));
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): pending-on-run-queue thread ");
  {
    queue_test_funct_data_t d3 = {0, 0, &queue, false, -1};
    kthread_create(&thread1, &queue_test_func, &d3);
    scheduler_make_runnable(thread1);

    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d3.waiting; ++i) scheduler_yield();
    KEXPECT_EQ(1, d3.waiting);
    KEXPECT_EQ(0, d3.ran);

    scheduler_wake_one(&queue);
    for (int i = 0; i < 5 && !d3.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d3.ran);

    KEXPECT_EQ(SWAIT_DONE, thread1->wait_status);
    KEXPECT_EQ((void*)0, kthread_join(thread1));
  }

  KTEST_BEGIN(
      "scheduler_interrupt_thread(): immediate return with pending signals");
  {
    proc_force_signal_on_thread(proc_current(), kthread_current_thread(),
                                SIGUSR1);
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue, -1));
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue, -1));
    KEXPECT_EQ(SWAIT_INTERRUPTED, kthread_current_thread()->wait_status);

    proc_suppress_signal(proc_current(), SIGUSR1);
    kthread_current_thread()->wait_status = SWAIT_DONE;
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): current thread (running)");
  KEXPECT_EQ((void*)0x0, kthread_current_thread()->queue);

  scheduler_interrupt_thread(kthread_current_thread());
  KEXPECT_EQ((void*)0x0, kthread_current_thread()->queue);
  KEXPECT_EQ(SWAIT_DONE, kthread_current_thread()->wait_status);

  // TODO(aoates): test a thread that does an interruptable wait followed by a
  // non-interruptable wait; verify that the second wait is uninterruptable, and
  // that the interrupted bit is reset.

  // TODO(aoates): stress/multi-threaded/interrupt test
}

static void scheduler_interrupt_timeout_test(void) {
  KTEST_BEGIN("scheduler_interrupt_thread(): interruptable thread w/ timeout");
  kthread_t thread1;

  kthread_queue_t queue;
  kthread_queue_init(&queue);

  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, 500};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_interrupt_thread(thread1);
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(SWAIT_INTERRUPTED, thread1->wait_status);
    KEXPECT_EQ(false, thread1->wait_timeout_ran);
    KEXPECT_EQ((void*)1, kthread_join(thread1));
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): interruptable wait times out");
  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, 200};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    apos_ms_t start = get_time_ms();
    for (int i = 0; i < 20 && !d1.ran; ++i) ksleep(20);
    apos_ms_t end = get_time_ms();
    KEXPECT_GE(end-start, 180);
    KEXPECT_LE(end-start, 250);
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(SWAIT_TIMEOUT, thread1->wait_status);
    KEXPECT_EQ(true, thread1->wait_timeout_ran);
    KEXPECT_EQ((void*)SWAIT_TIMEOUT, kthread_join(thread1));
  }

  KTEST_BEGIN("scheduler_interrupt_thread(): timeout doesn't fire");
  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, 5000};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    ksleep(100);
    scheduler_wake_all(&queue);
    apos_ms_t start = get_time_ms();
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_LE(get_time_ms() - start, 30);
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(SWAIT_DONE, thread1->wait_status);
    KEXPECT_EQ(false, thread1->wait_timeout_ran);
    KEXPECT_EQ((void*)0, kthread_join(thread1));
  }

  KTEST_BEGIN(
      "scheduler_interrupt_thread(): immediate return with pending signals "
      "(with timeout)");
  {
    proc_force_signal_on_thread(proc_current(), kthread_current_thread(),
                                SIGUSR1);
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue, 5000));
    KEXPECT_EQ(1, scheduler_wait_on_interruptable(&queue, 5000));
    KEXPECT_EQ(SWAIT_INTERRUPTED, kthread_current_thread()->wait_status);

    proc_suppress_signal(proc_current(), SIGUSR1);
    kthread_current_thread()->wait_status = SWAIT_DONE;
  }

  KTEST_BEGIN(
      "scheduler_interrupt_thread(): timeout fires after interrupt before its "
      "cancelled");
  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, 20};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_interrupt_thread(thread1);
    apos_ms_t start = get_time_ms();
    // Spin until the timeout (should have) fired.  We can't yield, since we
    // must ensure the thread we interrupted doesn't get a chance to run.
    while (get_time_ms() - start < 50);

    // Even though the timeout fired, the interrupt happened first.
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(true, thread1->wait_timeout_ran);
    KEXPECT_EQ(SWAIT_INTERRUPTED, thread1->wait_status);
    KEXPECT_EQ((void*)1, kthread_join(thread1));
  }

  KTEST_BEGIN(
      "scheduler sleep: timeout fires after normal wakeup before it's "
      "cancelled.");
  {
    queue_test_funct_data_t d1 = {0, 0, &queue, true, 20};
    kthread_create(&thread1, &queue_test_func, &d1);
    scheduler_make_runnable(thread1);
    while (!d1.waiting) scheduler_yield();

    KEXPECT_EQ(&queue, thread1->queue);
    scheduler_wake_all(&queue);
    apos_ms_t start = get_time_ms();
    // Spin until the timeout (should have) fired.  We can't yield, since we
    // must ensure the thread we woke up doesn't get a chance to run.
    while (get_time_ms() - start < 50);

    // Even though the timeout fired, the wakeup happened first.
    for (int i = 0; i < 5 && !d1.ran; ++i) scheduler_yield();
    KEXPECT_EQ(1, d1.ran);
    KEXPECT_EQ(true, thread1->wait_timeout_ran);
    KEXPECT_EQ(SWAIT_DONE, thread1->wait_status);
    KEXPECT_EQ((void*)SWAIT_DONE, kthread_join(thread1));
  }
}

static void* kthread_is_done_test_helper(void* arg) {
  KEXPECT_EQ(KTHREAD_RUNNING, kthread_current_thread()->state);
  KEXPECT_EQ(false, kthread_is_done(kthread_current_thread()));
  scheduler_wait_on((kthread_queue_t*)arg);
  return 0x0;
}

static void kthread_is_done_test(void) {
  KTEST_BEGIN("kthread_is_done(): unscheduled thread");
  kthread_t thread;
  kthread_queue_t queue;
  kthread_queue_init(&queue);
  KEXPECT_EQ(0, kthread_create(&thread, &kthread_is_done_test_helper, &queue));
  KEXPECT_EQ(KTHREAD_PENDING, thread->state);
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN("kthread_is_done(): scheduled thread");
  scheduler_make_runnable(thread);
  KEXPECT_EQ(KTHREAD_PENDING, thread->state);
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN("kthread_is_done(): blocked-on-queue thread");
  while (thread->queue != &queue) scheduler_yield();
  KEXPECT_EQ(KTHREAD_PENDING, thread->state);
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN("kthread_is_done(): finished thread");
  scheduler_wake_all(&queue);
  while (thread->state != KTHREAD_DONE) scheduler_yield();
  KEXPECT_EQ(true, kthread_is_done(thread));

  KEXPECT_EQ(NULL, kthread_join(thread));
}

#define STRESS_TEST_ITERS 1000
#define STRESS_TEST_THREADS 1000

static void* stress_test_func(void* arg) {
  int id = (int)(intptr_t)arg;
  if (id % 100 == 0) KLOG("THREAD %d START\n", (int)(intptr_t)arg);
  for (int i = 0; i < STRESS_TEST_ITERS; ++i) {
    scheduler_yield();
  }
  if (id % 100 == 0) KLOG("THREAD %d DONE\n", (int)(intptr_t)arg);
  return arg;
}

// TODO(aoates): make this random.
static void stress_test(void) {
  KTEST_BEGIN("stress test");
  kthread_t* threads = (kthread_t*)kmalloc(sizeof(kthread_t) * STRESS_TEST_THREADS);

  for (intptr_t i = 0; i < STRESS_TEST_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i], &stress_test_func, (void*)i) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    KEXPECT_EQ(i, (intptr_t)kthread_join(threads[i]));
  }

  kfree(threads);
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

typedef struct {
  int x;
  kspinlock_t lock;
  kspinlock_intsafe_t intsafe_lock;
} preemption_test_args_t;

static void* preemption_test_worker(void* arg) {
  preemption_test_args_t* args = (preemption_test_args_t*)arg;
  for (int i = 0; i < 100000; ++i) {
    kspin_lock(&args->lock);
    for (volatile int i = 0; i < 1000; ++i);
    args->x++;
    kspin_unlock(&args->lock);
  }
  return NULL;
}

static void preemption_test_defintA(void* arg) {
  preemption_test_args_t* args = (preemption_test_args_t*)arg;
  args->x++;
}

static void preemption_test_defintB(void* arg) {
  preemption_test_args_t* args = (preemption_test_args_t*)arg;
  kspin_lock(&args->lock);
  args->x++;
  kspin_unlock(&args->lock);
}

static void preemption_test_defintC(void* arg) {
  preemption_test_args_t* args = (preemption_test_args_t*)arg;
  // Must be read without the lock.
  int val = kthread_current_thread()->preemption_disables > 0 ? 1 : 2;
  kspin_lock(&args->lock);
  args->x = val;
  kspin_unlock(&args->lock);
}

static void* preemption_test_check_enabled(void* arg) {
  return (void*)(intptr_t)kthread_current_thread()->preemption_disables;
}

static void preemption_test_interrupt_cb(void* arg) {
  preemption_test_args_t* args = (preemption_test_args_t*)arg;
  kspin_lock_int(&args->intsafe_lock);
  args->x++;
  kspin_unlock_int(&args->intsafe_lock);
}

static void* preemption_test_tester(void* arg) {
  sched_enable_preemption_for_test();

  preemption_test_args_t args;
  args.x = 0;
  args.lock = KSPINLOCK_NORMAL_INIT;
  kthread_t worker = 0x0;
  int result = kthread_create(&worker, &preemption_test_worker, &args);
  KEXPECT_EQ(0, result);
  scheduler_make_runnable(worker);

  for (int i = 0; i < 1000; ++i) {
    for (volatile int j = 0; j < 1000000; ++j)
      ;
    kspin_lock(&args.lock);
    int xval = args.x;
    kspin_unlock(&args.lock);
    if (xval) break;
  }
  kspin_lock(&args.lock);
  KEXPECT_GT(args.x, 0);
  kspin_unlock(&args.lock);

  // With a spinlock held, the value should _not_ be updated.
  kspin_lock(&args.lock);
  int init_val = args.x;
  for (volatile int i = 0; i < 100000; ++i)
    ;
  KEXPECT_EQ(init_val, args.x);
  kspin_unlock(&args.lock);
  kthread_join(worker);

  KTEST_BEGIN("kthread: spinlock disables defints");
  kspin_lock(&args.lock);
  {
    DEFINT_PUSH_AND_DISABLE();
    args.x = 0;
    // One just increments, the other does so with a spinlock.
    defint_schedule(&preemption_test_defintA, &args);
    defint_schedule(&preemption_test_defintB, &args);
    DEFINT_POP();
  }
  apos_ms_t start = get_time_ms();
  for (volatile int i = 0; (get_time_ms() - start) < 30; ++i);
  KEXPECT_EQ(0, args.x);

  // Let the defints run.
  while (args.x < 2) {
    kspin_unlock(&args.lock);
    ksleep(1);
    kspin_lock(&args.lock);
  }
  kspin_unlock(&args.lock);

  KTEST_BEGIN("kthread: defint disable preemption");
  {
    DEFINT_PUSH_AND_DISABLE();
    defint_schedule(&preemption_test_defintC, &args);
    DEFINT_POP();
  }
  start = get_time_ms();
  for (volatile int i = 0; (get_time_ms() - start) < 30; ++i);
  KEXPECT_EQ(1, args.x);

  KTEST_BEGIN("kthread: preemption state inherited in child threads");
  kthread_t child = NULL;
  {
    sched_disable_preemption();
    sched_disable_preemption();
    KEXPECT_EQ(0, kthread_create(&child, &preemption_test_check_enabled, NULL));
    scheduler_make_runnable(child);
    KEXPECT_EQ(1, (intptr_t)kthread_join(child));
    sched_restore_preemption();
    sched_restore_preemption();
  }
  KEXPECT_EQ(0, kthread_create(&child, &preemption_test_check_enabled, NULL));
  scheduler_make_runnable(child);
  KEXPECT_EQ(0, (intptr_t)kthread_join(child));

  KTEST_BEGIN("kthread: SPINLOCK_INTERRUPT_SAFE blocks interrupts");
  preemption_test_args_t interrupt_args;
  interrupt_args.intsafe_lock = KSPINLOCK_INTERRUPT_SAFE_INIT;
  interrupt_args.x = 0;
  const int kTimerLimit = 50;
  const unsigned int kDurationLimitMs = 10 * 1000;
  KEXPECT_EQ(
      0, register_timer_callback(1, kTimerLimit, &preemption_test_interrupt_cb,
                                 &interrupt_args));
  int my_counter = 0;
  int last_val = 0;
  start = get_time_ms();
  while (last_val - my_counter < kTimerLimit &&
         get_time_ms() - start < kDurationLimitMs) {
    // Do an explicit two-stage increment.
    kspin_lock_int(&interrupt_args.intsafe_lock);
    int cval = *(volatile int*)&interrupt_args.x;
    for (volatile int i = 0; i < 1000; ++i);
    *(volatile int*)&interrupt_args.x = cval + 1;
    last_val = cval + 1;
    my_counter++;
    kspin_unlock_int(&interrupt_args.intsafe_lock);
  }
  KEXPECT_EQ(my_counter + kTimerLimit, interrupt_args.x);

  return NULL;
}

static void preemption_test(void) {
  KTEST_BEGIN("kthread preemption test");

  // Spin the test off in another thread to ensure preemption state is preserved
  // for the main thread.
  kthread_t tester = 0x0;
  int result = kthread_create(&tester, &preemption_test_tester, NULL);
  KEXPECT_EQ(0, result);
  scheduler_make_runnable(tester);
  kthread_join(tester);
}

typedef struct {
  kmutex_t* mu;
  kspinlock_t* sp;
  kthread_queue_t* queue;
  bool* val;  // Shared state between the test threads.
  bool who_am_i;  // Different for each test thread.
} wait_on_locked_test_args;

static void* wait_on_locked_test_thread(void* arg) {
  sched_enable_preemption_for_test();
  wait_on_locked_test_args* args = (wait_on_locked_test_args*)arg;

  for (int i = 0; i < 3000; ++i) {
    kmutex_lock(args->mu);
    while (*args->val != args->who_am_i) {
      scheduler_wait_on_locked(args->queue, -1, args->mu);
    }
    *args->val = !args->who_am_i;
    scheduler_wake_all(args->queue);
    kmutex_unlock(args->mu);
  }
  return NULL;
}

static void wait_on_locked_test(void) {
  KTEST_BEGIN("scheduler_wait_on_locked test");

  kthread_t threadA, threadB;
  kmutex_t mu;
  kthread_queue_t queue;
  bool shared_val = false;

  wait_on_locked_test_args argsA, argsB;
  argsA.mu = &mu;
  argsA.queue = &queue;
  argsA.val = &shared_val;
  argsA.who_am_i = false;
  argsB = argsA;
  argsB.who_am_i = true;

  kmutex_init(&mu);
  kthread_queue_init(&queue);
  KEXPECT_EQ(0, kthread_create(&threadA, &wait_on_locked_test_thread, &argsA));
  KEXPECT_EQ(0, kthread_create(&threadB, &wait_on_locked_test_thread, &argsB));
  scheduler_make_runnable(threadA);
  scheduler_make_runnable(threadB);

  kthread_join(threadA);
  kthread_join(threadB);

  KTEST_BEGIN("scheduler_wait_on_locked interruptable test");
  proc_alarm_ms(50);
  kmutex_lock(&mu);
  KEXPECT_EQ(SWAIT_INTERRUPTED, scheduler_wait_on_locked(&queue, -1, &mu));
  proc_suppress_signal(proc_current(), SIGALRM);
  kmutex_unlock(&mu);

  KTEST_BEGIN("scheduler_wait_on_locked timeout test");
  kmutex_lock(&mu);
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_locked(&queue, 30, &mu));
  kmutex_unlock(&mu);
}

static void* wait_on_spin_locked_test_thread(void* arg) {
  sched_enable_preemption_for_test();
  wait_on_locked_test_args* args = (wait_on_locked_test_args*)arg;

  for (int i = 0; i < 3000; ++i) {
    kspin_lock(args->sp);
    while (*args->val != args->who_am_i) {
      scheduler_wait_on_splocked(args->queue, -1, args->sp);
    }
    *args->val = !args->who_am_i;
    scheduler_wake_all(args->queue);
    kspin_unlock(args->sp);
  }
  return NULL;
}

static void wait_on_spin_locked_test(void) {
  KTEST_BEGIN("scheduler_wait_on_splocked test");

  kthread_t threadA, threadB;
  kspinlock_t sp = KSPINLOCK_NORMAL_INIT;
  kthread_queue_t queue;
  bool shared_val = false;

  wait_on_locked_test_args argsA, argsB;
  argsA.sp = &sp;
  argsA.queue = &queue;
  argsA.val = &shared_val;
  argsA.who_am_i = false;
  argsB = argsA;
  argsB.who_am_i = true;

  kthread_queue_init(&queue);
  KEXPECT_EQ(
      0, kthread_create(&threadA, &wait_on_spin_locked_test_thread, &argsA));
  KEXPECT_EQ(
      0, kthread_create(&threadB, &wait_on_spin_locked_test_thread, &argsB));
  scheduler_make_runnable(threadA);
  scheduler_make_runnable(threadB);

  kthread_join(threadA);
  kthread_join(threadB);

  KTEST_BEGIN("scheduler_wait_on_splocked interruptable test");
  proc_alarm_ms(50);
  kspin_lock(&sp);
  KEXPECT_EQ(SWAIT_INTERRUPTED, scheduler_wait_on_splocked(&queue, -1, &sp));
  proc_suppress_signal(proc_current(), SIGALRM);
  kspin_unlock(&sp);

  KTEST_BEGIN("scheduler_wait_on_locked timeout test");
  kspin_lock(&sp);
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_splocked(&queue, 30, &sp));
  kspin_unlock(&sp);
}

typedef struct {
  // TODO(aoates): use Notification.
  kthread_queue_t queue;
  bool x;
} disable_test_args_t;

static void* disable_test_thread(void* arg) {
  disable_test_args_t* args = (disable_test_args_t*)arg;
  scheduler_wake_all(&args->queue);
  scheduler_wait_on(&args->queue);
  args->x = true;
  return NULL;
}

typedef struct {
  kmutex_t* mu;
  notification_t started;
  notification_t done;
} disable_test2_args_t;

static void* disable_test_thread2(void* arg) {
  disable_test2_args_t* args = (disable_test2_args_t*)arg;
  ntfn_notify(&args->started);
  kmutex_lock(args->mu);
  kmutex_unlock(args->mu);
  ntfn_notify(&args->done);
  return NULL;
}

void disable_test2_args_init(disable_test2_args_t* args, kmutex_t* mu) {
  args->mu = mu;
  ntfn_init(&args->started);
  ntfn_init(&args->done);
}

static void disable_test(void) {
  KTEST_BEGIN("kthread_disable() test");
  disable_test_args_t args;
  kthread_queue_init(&args.queue);
  args.x = false;

  kthread_t thread;
  KEXPECT_EQ(0,kthread_create(&thread, &disable_test_thread, &args));
  scheduler_make_runnable(thread);
  scheduler_wait_on(&args.queue);
  // The other thread is now running.  Disable it, then wake it.
  kthread_disable(thread);
  scheduler_wake_all(&args.queue);
  for (int i = 0; i < 10; ++i) scheduler_yield();
  // The thread should not have run.
  KEXPECT_FALSE(args.x);

  // Re-enable the thread, then it should be able to run.
  kthread_enable(thread);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_TRUE(args.x);


  KTEST_BEGIN("kthread_disable() with mutex test (one disabled thread)");
  kmutex_t mu;
  kmutex_init(&mu);
  kmutex_lock(&mu);
  const int kNumArgs = 2;
  disable_test2_args_t args2[kNumArgs];
  for (int i = 0; i < kNumArgs; ++i) {
    disable_test2_args_init(&args2[i], &mu);
  }
  KEXPECT_EQ(0, kthread_create(&thread, disable_test_thread2, &args2));
  scheduler_make_runnable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[0].started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));
  kthread_disable(thread);
  kmutex_unlock(&mu);
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));  // It's disabled.
  kthread_enable(thread);
  KEXPECT_EQ(NULL, kthread_join(thread));


  KTEST_BEGIN("kthread_disable() with mutex test (two disabled threads)");
  kmutex_lock(&mu);
  for (int i = 0; i < kNumArgs; ++i) {
    disable_test2_args_init(&args2[i], &mu);
  }
  kthread_t thread2;
  KEXPECT_EQ(0, kthread_create(&thread, disable_test_thread2, &args2[0]));
  KEXPECT_EQ(0, kthread_create(&thread2, disable_test_thread2, &args2[1]));
  scheduler_make_runnable(thread);
  scheduler_make_runnable(thread2);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[0].started, 5000));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[1].started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[1].done, 20));
  kthread_disable(thread);
  kthread_disable(thread2);
  kmutex_unlock(&mu);
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));  // It's disabled.
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[1].done, 20));  // It's disabled.
  kthread_enable(thread);
  kthread_enable(thread2);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(NULL, kthread_join(thread2));

  // Create two threads that try to lock a mutex.  The one that is not disabled
  // should be prioritized even though it locks second.
  KTEST_BEGIN("kthread_disable() with mutex test (mixed disabled threads)");
  kmutex_lock(&mu);
  for (int i = 0; i < kNumArgs; ++i) {
    disable_test2_args_init(&args2[i], &mu);
  }
  KEXPECT_EQ(0, kthread_create(&thread, disable_test_thread2, &args2[0]));
  KEXPECT_EQ(0, kthread_create(&thread2, disable_test_thread2, &args2[1]));
  scheduler_make_runnable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[0].started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));
  scheduler_make_runnable(thread2);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[1].started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[1].done, 20));
  kthread_disable(thread);
  kmutex_unlock(&mu);
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2[0].done, 20));  // It's disabled.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2[1].done, 5000));
  kthread_enable(thread);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(NULL, kthread_join(thread2));
}

static void* do_notify(void* arg) {
  ksleep(50);
  ntfn_notify((notification_t*)arg);
  return NULL;
}

static void notification_test(void) {
  KTEST_BEGIN("notification: basic test");
  notification_t n;
  ntfn_init(&n);
  KEXPECT_FALSE(ntfn_has_been_notified(&n));
  KEXPECT_FALSE(ntfn_has_been_notified(&n));

  ntfn_notify(&n);
  KEXPECT_TRUE(ntfn_has_been_notified(&n));
  ntfn_await(&n);
  KEXPECT_TRUE(ntfn_await_with_timeout(&n, 1000));
  ntfn_await(&n);

  KTEST_BEGIN("notification: wait test");
  kthread_t thread;
  ntfn_init(&n);
  KEXPECT_EQ(0, kthread_create(&thread, &do_notify, &n));
  scheduler_make_runnable(thread);

  apos_ms_t start = get_time_ms();
  ntfn_await(&n);
  KEXPECT_TRUE(ntfn_has_been_notified(&n));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 30);
  KEXPECT_LE(end - start, 200);
  KEXPECT_EQ(NULL, kthread_join(thread));

  KTEST_BEGIN("notification: wait with timeout test");
  ntfn_init(&n);

  start = get_time_ms();
  KEXPECT_FALSE(ntfn_await_with_timeout(&n, 100));
  KEXPECT_FALSE(ntfn_has_been_notified(&n));
  end = get_time_ms();
  KEXPECT_GE(end - start, 100);
  KEXPECT_LE(end - start, 500);

  KEXPECT_EQ(0, kthread_create(&thread, &do_notify, &n));
  scheduler_make_runnable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&n, 500));
  KEXPECT_TRUE(ntfn_has_been_notified(&n));

  start = get_time_ms();
  KEXPECT_TRUE(ntfn_await_with_timeout(&n, 500));
  end = get_time_ms();
  KEXPECT_LE(end - start, 50);
  KEXPECT_TRUE(ntfn_has_been_notified(&n));
  KEXPECT_EQ(NULL, kthread_join(thread));
}

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
static void* dldet_thread(void* arg) {
  kmutex_t A, B, C;
  const int kNumMus = KMUTEX_DEADLOCK_LRU_SIZE - 1;
  kmutex_t mus[kNumMus];
  kmutex_init(&A);
  kmutex_init(&B);
  kmutex_init(&C);
  for (int i = 0; i < kNumMus; ++i) {
    kmutex_init(&mus[i]);
  }
  // Test mutexes -- always locked in reverse order (so A is locked last, with
  // all the rest as priors -- looking at the 'priors' set of A in the tests).
  kthread_t me = kthread_current_thread();

  // First test basic mutex held list maintenance.
  KEXPECT_EQ(0, list_size(&me->mutexes_held));
  kmutex_lock(&A);
  KEXPECT_EQ(1, list_size(&me->mutexes_held));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &A.link));
  kmutex_unlock(&A);
  KEXPECT_EQ(0, list_size(&me->mutexes_held));
  KEXPECT_FALSE(list_link_on_list(&me->mutexes_held, &A.link));
  kmutex_lock(&B);
  KEXPECT_EQ(1, list_size(&me->mutexes_held));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &B.link));
  kmutex_unlock(&B);

  // Neither should have a prior still.
  KEXPECT_EQ(0, A.priors[0].id);
  KEXPECT_EQ(0, B.priors[0].id);

  // Lock B, then A.
  kmutex_lock(&B);
  kmutex_lock(&A);
  KEXPECT_EQ(2, list_size(&me->mutexes_held));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &A.link));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &B.link));

  KEXPECT_EQ(0, B.priors[0].id);
  KEXPECT_EQ(B.id, A.priors[0].id);
  KEXPECT_EQ(0, A.priors[1].id);
  kmutex_unlock(&A);
  kmutex_unlock(&B);

  // Now sleep, then lock C, then A.  A should have both 'B' and 'C' in the
  // priors set, with C with a higher LRU value.
  ksleep(10);
  kmutex_lock(&C);
  kmutex_lock(&A);
  KEXPECT_EQ(2, list_size(&me->mutexes_held));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &A.link));
  KEXPECT_TRUE(list_link_on_list(&me->mutexes_held, &C.link));

  KEXPECT_EQ(0, C.priors[0].id);
  KEXPECT_EQ(B.id, A.priors[0].id);
  KEXPECT_EQ(C.id, A.priors[1].id);
  KEXPECT_EQ(0, A.priors[2].id);
  KEXPECT_GT(A.priors[1].lru, A.priors[0].lru);
  const apos_ms_t oldBlru = A.priors[0].lru;
  const apos_ms_t oldClru = A.priors[1].lru;
  kmutex_unlock(&A);
  kmutex_unlock(&C);

  // Now overflow the LRU and make sure we replace the oldest one first.
  ksleep(10);
  for (int i = 0; i < kNumMus - 1; ++i) {
    kmutex_lock(&mus[i]);
  }
  kmutex_lock(&B);
  kmutex_lock(&A);

  // A's priors list should have been updated -- the LRU for B should now be
  // higher than the one for C.
  KEXPECT_EQ(B.id, A.priors[0].id);
  KEXPECT_EQ(C.id, A.priors[1].id);
  KEXPECT_NE(0, A.priors[2].id);
  KEXPECT_GT(A.priors[0].lru, oldBlru);
  KEXPECT_EQ(A.priors[1].lru, oldClru);
  kmutex_unlock(&B);

  ksleep(10);
  // Lock one more mutex.  This should now evict C.
  kmutex_unlock(&A);
  kmutex_lock(&mus[kNumMus - 1]);
  kmutex_lock(&A);
  KEXPECT_EQ(B.id, A.priors[0].id);
  KEXPECT_EQ(mus[kNumMus - 1].id, A.priors[1].id);  // not C
  KEXPECT_GT(A.priors[0].lru, oldBlru);
  KEXPECT_GT(A.priors[1].lru, A.priors[0].lru);
  kmutex_unlock(&A);
  kmutex_unlock(&mus[kNumMus - 1]);
  for (int i = kNumMus - 2; i >= 0; --i) {
    kmutex_unlock(&mus[i]);
  }

  KTEST_BEGIN("kmutex_t same-address deadlock detection test");
  kmutex_init(&A);
  kmutex_init(&B);
  kmutex_lock(&B);
  kmutex_lock(&A);
  kmutex_unlock(&A);
  kmutex_unlock(&B);

  // Re-initialize B --- we should not trigger a deadlock detection, even though
  // they're at the same address.
  ksleep(10);
  kmutex_init(&B);
  kmutex_lock(&A);
  kmutex_lock(&B);  // Should be OK --- new 'B' won't be in A's priors.
  kmutex_unlock(&B);
  kmutex_unlock(&A);

  // If enabled, test an actual deadlock --- this will panic.
  if (RUN_DEADLOCK_DETECTION_FALIURE_TEST) {
    KTEST_BEGIN("kmutex_t actual deadlock");
    kmutex_init(&A);
    kmutex_init(&B);
    kmutex_lock(&A);
    kmutex_lock(&B);
    kmutex_unlock(&B);
    kmutex_unlock(&A);

    kmutex_lock(&B);
    kmutex_lock(&A);  // Should die here.
    die("should NOT have gotten here");
  }

  return NULL;
}

static void deadlock_detection_test(void) {
  KTEST_BEGIN("kmutex_t deadlock detection test");
  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &dldet_thread, NULL));
  scheduler_make_runnable(thread);
  KEXPECT_EQ(NULL, kthread_join(thread));
}
#endif

static void* interrupts_checker(void* arg) {
  KEXPECT_TRUE(interrupts_enabled());
  KEXPECT_TRUE(defint_state());
  return NULL;
}

static void creation_interrupts_test(void) {
  KTEST_BEGIN("kthread interrupt state on creation test");
  kthread_t thread;

  DEFINT_PUSH_AND_DISABLE();
  PUSH_AND_DISABLE_INTERRUPTS();
  KEXPECT_EQ(0, kthread_create(&thread, &interrupts_checker, NULL));
  scheduler_make_runnable(thread);
  KEXPECT_EQ(NULL, kthread_join(thread));
  POP_INTERRUPTS();
  DEFINT_POP();
}

typedef struct {
  refcount_t ref;
  kspinlock_t spin;
  int deletes;
} refcount_test_args_t;

static void refcount_test_defint(void* arg) {
  refcount_test_args_t* args = (refcount_test_args_t*)arg;
  if (refcount_dec(&args->ref) == 0) {
    kspin_lock(&args->spin);
    args->deletes++;
    kspin_unlock(&args->spin);
  }
}

static void* refcount_test_thread(void* arg) {
  sched_enable_preemption_for_test();
  const int kNumIters = 3000 * CONCURRENCY_TEST_ITERS_MULT;

  refcount_test_args_t* args = (refcount_test_args_t*)arg;
  for (int i = 0; i < kNumIters; ++i) {
    refcount_inc(&args->ref);
    KASSERT(refcount_dec(&args->ref) > 0);
    if (i % 100 == 0) {
      refcount_inc(&args->ref);
      defint_schedule(refcount_test_defint, arg);
    }
    if (i % 1000 == 0) {
      ksleep(10);
    }
  }

  if (refcount_dec(&args->ref) == 0) {
    kspin_lock(&args->spin);
    args->deletes++;
    kspin_unlock(&args->spin);
  }
  return NULL;
}

static refcount_t static_ref_test = REFCOUNT_INIT;

static void refcount_test(void) {
  KTEST_BEGIN("refcount_t static init test");
  refcount_inc(&static_ref_test);
  KEXPECT_EQ(1, refcount_dec(&static_ref_test));

  KTEST_BEGIN("refcount_t test");
  const int kNumThreads = 10 * CONCURRENCY_TEST_THREADS_MULT;
  kthread_t threads[kNumThreads];
  refcount_test_args_t args;
  args.ref = REFCOUNT_INIT;
  args.spin = KSPINLOCK_NORMAL_INIT;
  args.deletes = 0;

  for (int i = 0; i < kNumThreads; ++i) {
    refcount_inc(&args.ref);
    KEXPECT_EQ(0, kthread_create(&threads[i], &refcount_test_thread, &args));
  }

  KASSERT(refcount_dec(&args.ref) > 0);
  for (int i = 0; i < kNumThreads; ++i) {
    scheduler_make_runnable(threads[i]);
  }
  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
  KEXPECT_EQ(0, args.ref.ref);
  KEXPECT_EQ(1, args.deletes);
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
  scheduler_wake_race_test();
  scheduler_wake_all_race_test();
  scheduler_interrupt_test();
  scheduler_interrupt_timeout_test();
  kthread_is_done_test();
  stress_test();
  kmutex_test();
  kmutex_auto_lock_test();
  ksleep_test();
  preemption_test();
  wait_on_locked_test();
  wait_on_spin_locked_test();
  disable_test();
  notification_test();
#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  deadlock_detection_test();
#endif
  creation_interrupts_test();
  refcount_test();
}
