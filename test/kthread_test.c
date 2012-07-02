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
#include "test/ktest.h"

// TODO(aoates): other things to test:
//  * multiple threads join()'d onto one thread

static void* thread_func(void* arg) {
  int id = (int)arg;
  klogf("THREAD STARTED: %d\n", id);
  for (int i = 0; i < 3; ++i) {
    klogf("THREAD ITER: %d (iter %d)\n", id, i);
    kthread_yield();
  }
  klogf("THREAD %d: done\n", id);
  return 0;
}

static void yield_test() {
  // Repeatedly yield and make sure we get to the end.
  KTEST_BEGIN("trivial yield test");

  kthread_yield();
  kthread_yield();
  kthread_yield();

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

  kthread_join(&thread1);
  kthread_join(&thread2);
  kthread_join(&thread3);

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
  KEXPECT_EQ(0xabcd, (uint32_t)kthread_join(&thread1));
}

static void* kthread_return_thread_func(void* arg) {
  return arg;
}

static void kthread_return_test() {
  KTEST_BEGIN("explicit return test");
  kthread_t thread1;

  KASSERT(kthread_create(&thread1, &kthread_return_thread_func, (void*)0xabcd));
  KEXPECT_EQ(0xabcd, (uint32_t)kthread_join(&thread1));
}

#define STRESS_TEST_ITERS 1000
#define STRESS_TEST_THREADS 1000

static void* stress_test_func(void* arg) {
  klogf("THREAD %d START\n", (int)arg);
  for (int i = 0; i < STRESS_TEST_ITERS; ++i) {
    kthread_yield();
  }
  klogf("THREAD %d DONE\n", (int)arg);
  return arg;
}

// TODO(aoates): make this random.
static void stress_test() {
  KTEST_BEGIN("stress test");
  kthread_t* threads[STRESS_TEST_THREADS];

  for (int i = 0; i < STRESS_TEST_THREADS; ++i) {
    threads[i] = (kthread_t*)kmalloc(sizeof(kthread_t));
    KASSERT(kthread_create(threads[i], &stress_test_func, (void*)i));
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
  stress_test();
}
