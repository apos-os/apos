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

#include "common/atomic.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "dev/timer.h"
#include "proc/kthread_pool.h"
#include "proc/sleep.h"
#include "proc/scheduler.h"
#include "test/ktest.h"

static atomic32_t counter;
static kthread_queue_t wait_queue;

static void pool_cb(void* arg) {
  scheduler_yield();
  int val = atomic_sub_relaxed(&counter, 1);
  scheduler_yield();

  if (val == 0) {
    scheduler_make_runnable(kthread_queue_pop(&wait_queue));
  }
}

static void timer_cb(void* arg) {
  kthread_pool_t* pool = (kthread_pool_t*)arg;
  int result = kthread_pool_push(pool, &pool_cb, arg);
  if (result != 0) {
    KLOG("ERROR: couldn't kthread_pool_push: %s\n",
         errorname(-result));
    KASSERT(result == 0);
  }
}

#define TEST_SIZE 100
#define POOL_SIZE 5

void kthread_pool_test(void) {
  KTEST_SUITE_BEGIN("kthread_pool");
  KTEST_BEGIN("kthread_pool");

  atomic_store_relaxed(&counter, TEST_SIZE);
  kthread_pool_t pool;
  KASSERT(0 == kthread_pool_init(&pool, POOL_SIZE));
  scheduler_yield();  // Check the empty-queue logic.
  kthread_queue_init(&wait_queue);

  register_timer_callback(1, TEST_SIZE / 2, &timer_cb, &pool);
  for (int i = 0; i < TEST_SIZE / 2; ++i) {
    int result = kthread_pool_push(&pool, &pool_cb, &pool);
    if (result != 0) {
      KLOG("ERROR: couldn't kthread_pool_push: %s\n",
           errorname(-result));
      KASSERT(result == 0);
    }
  }

  scheduler_wait_on(&wait_queue);
  // Give any extra threads a chance to run (which would be an error --- we
  // shouldn't get here until everything is finished).
  ksleep(100);

  KEXPECT_EQ(atomic_load_relaxed(&counter), 0);

  KTEST_BEGIN("kthread_pool_destroy(): blocks for pending items");
  atomic_store_relaxed(&counter, POOL_SIZE + 4);
  for (int i = 0; i < POOL_SIZE + 3; ++i)
    kthread_pool_push(&pool, &pool_cb, NULL);
  kthread_pool_destroy(&pool);
  KEXPECT_EQ(1, atomic_load_relaxed(&counter));
}
