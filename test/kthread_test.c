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
#include "kmalloc.h"
#include "kthread.h"
#include "scheduler.h"
#include "test/ktest.h"

// TODO(aoates): other things to test:
//  * multiple threads join()'d onto one thread

static void* thread_func(void* arg) {
  int id = (int)arg;
  klogf("THREAD STARTED: %d\n", id);
  for (int i = 0; i < 3; ++i) {
    klogf("THREAD ITER: %d (iter %d)\n", id, i);
    scheduler_yield();
  }
  klogf("THREAD %d: done\n", id);
  return 0;
}

static void yield_test() {
  // Repeatedly yield and make sure we get to the end.
  KTEST_BEGIN("trivial yield test");

  scheduler_yield();
  scheduler_yield();
  scheduler_yield();

  klogf("  DONE\n");
}

static void basic_test() {
  KTEST_BEGIN("basic test");
  kthread_t thread1;
  kthread_t thread2;
  kthread_t thread3;

  KASSERT(kthread_create(&thread1, &thread_func, (void*)1));
  KASSERT(kthread_create(&thread2, &thread_func, (void*)2));
  KASSERT(kthread_create(&thread3, &thread_func, (void*)3));

  scheduler_make_runnable(thread1);
  scheduler_make_runnable(thread2);
  scheduler_make_runnable(thread3);

  kthread_join(thread1);
  kthread_join(thread2);
  kthread_join(thread3);

  klogf("MAIN THREAD: done\n");
}

static void* kthread_exit_thread_func(void* arg) {
  kthread_exit(arg);
  KASSERT(0);
  return 0;
}

static void kthread_exit_test() {
  KTEST_BEGIN("kthread_exit() test");
  kthread_t thread1;

  KASSERT(kthread_create(&thread1, &kthread_exit_thread_func, (void*)0xabcd));
  scheduler_make_runnable(thread1);
  KEXPECT_EQ(0xabcd, (uint32_t)kthread_join(thread1));
}

static void* kthread_return_thread_func(void* arg) {
  return arg;
}

static void kthread_return_test() {
  KTEST_BEGIN("explicit return test");
  kthread_t thread1;

  KASSERT(kthread_create(&thread1, &kthread_return_thread_func, (void*)0xabcd));
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
static void join_chain_test() {
  KTEST_BEGIN("chained join test");

  kthread_t threads[JOIN_CHAIN_TEST_SIZE];
  for (int i = 0; i < JOIN_CHAIN_TEST_SIZE; i++) {
    kthread_t target = i > 0 ? threads[i-1] : 0;
    int result = kthread_create(&threads[i], &join_test_func, (void*)target);
    KASSERT(result != 0);
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
  KASSERT(kthread_create(&next, &join_test2_func, (void*)(x-1)));
  scheduler_make_runnable(next);
  return (void*)(1 + (int)kthread_join(next));
}

// Chain together a bunch of joined threads.  This time, each thread CREATES the
// next thread in the chain.
static void join_chain_test2() {
  KTEST_BEGIN("chained join test #2");

  kthread_t thread;
  int result = kthread_create(&thread, &join_test2_func,
                              (void*)JOIN_CHAIN_TEST_SIZE);
  KASSERT(result != 0);
  scheduler_make_runnable(thread);

  int out = (int)kthread_join(thread);
  KEXPECT_EQ(JOIN_CHAIN_TEST_SIZE, out);
}

#define STRESS_TEST_ITERS 1000
#define STRESS_TEST_THREADS 1000

static void* stress_test_func(void* arg) {
  klogf("THREAD %d START\n", (int)arg);
  for (int i = 0; i < STRESS_TEST_ITERS; ++i) {
    scheduler_yield();
  }
  klogf("THREAD %d DONE\n", (int)arg);
  return arg;
}

// TODO(aoates): make this random.
static void stress_test() {
  KTEST_BEGIN("stress test");
  kthread_t threads[STRESS_TEST_THREADS];

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i], &stress_test_func, (void*)i));
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    KEXPECT_EQ(i, (int)kthread_join(threads[i]));
  }

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    kfree(threads[i]);
  }
}

void kthread_test() {
  KTEST_SUITE_BEGIN("kthread_test");

  yield_test();
  basic_test();
  kthread_exit_test();
  kthread_return_test();
  join_chain_test();
  join_chain_test2();
  stress_test();
}
