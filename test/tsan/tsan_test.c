// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "proc/kthread.h"
#include "proc/process.h"
#include "test/kernel_tests.h"

#include "memory/kmalloc.h"
#include "test/ktest.h"
#include "test/tsan/instrumented.h"

typedef struct {
  kmutex_t mu;
  int* val;
} mutex_test_args_t;

static void tsan_basic_sanity_test(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value instrumentation");
  int* x = KMALLOC(int);
  *x = 0;
  tsan_rw_value(x);
  KEXPECT_EQ(1, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(2, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(3, *x);
  kfree(x);
}

static void* rw_value_thread(void* arg) {
  int* x = (int*)arg;
  tsan_rw_value(x);
  tsan_rw_value(x);
  return NULL;
}

static void tsan_basic_sanity_test2(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value instrumentation (two threads)");
  int* x = KMALLOC(int);
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread, x));
  tsan_rw_value(x);
  tsan_rw_value(x);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(4, *x);
  kfree(x);
}

static void* rw_value_thread_kmutex(void* arg) {
  mutex_test_args_t* args = (mutex_test_args_t*)arg;
  kmutex_lock(&args->mu);
  tsan_rw_value(args->val);
  kmutex_unlock(&args->mu);
  kmutex_lock(&args->mu);
  tsan_rw_value(args->val);
  kmutex_unlock(&args->mu);
  return NULL;
}

static void tsan_basic_sanity_test3(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, locked)");
  mutex_test_args_t args;
  kmutex_init(&args.mu);
  args.val = KMALLOC(int);
  *args.val = 0;
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread_kmutex, &args));

  kmutex_lock(&args.mu);
  tsan_rw_value(args.val);
  kmutex_unlock(&args.mu);
  kmutex_lock(&args.mu);
  tsan_rw_value(args.val);
  kmutex_unlock(&args.mu);

  KEXPECT_EQ(NULL, kthread_join(thread));
  // A join should act as a synchronization point between the threads.
  tsan_rw_value(args.val);

  KEXPECT_EQ(5, *args.val);
  kfree(args.val);
}

static void basic_tests(void) {
  tsan_basic_sanity_test();
#if 0
  // TODO(tsan): catch this failure in the test framework.
  tsan_basic_sanity_test2();
#endif
  tsan_basic_sanity_test3();
}

void tsan_test(void) {
  KTEST_SUITE_BEGIN("TSAN");
  basic_tests();
}
