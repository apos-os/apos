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

static void* thread_func(void* arg) {
  int id = (int)arg;
  klogf("THREAD STARTED: %d\n", id);
  for (int i = 0; i < 3; ++i) {
    klogf("THREAD ITER: %d (iter %d)\n", id, i);
    kthread_yield();
  }
  klogf("THREAD %d: done\n", id);
  return (void*)0;
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
  kthread_t thread1;
  KASSERT(kthread_create(&thread1, &thread_func, (void*)1));
  kthread_join(&thread1);

  klogf("MAIN THREAD: done\n");
}

void kthread_test() {
  KTEST_SUITE_BEGIN("kthread_test");

  yield_test();
  basic_test();
}
