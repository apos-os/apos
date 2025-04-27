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
#include "proc/defint_timer.h"
#include "proc/kthread_pool.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
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

struct defint_timer_arg {
  kthread_pool_t* pool;
  atomic32_t count;
};

static void defint_timer_pool_cb(defint_timer_t* timer, void* arg) {
  struct defint_timer_arg* timer_arg = (struct defint_timer_arg*)arg;
  kthread_pool_t* pool = timer_arg->pool;

  int result = kthread_pool_push(pool, &pool_cb, pool);
  if (result != 0) {
    KLOG("ERROR: couldn't kthread_pool_push: %s\n",
         errorname(-result));
    KASSERT(result == 0);
  }

  if (atomic_sub_acq_rel(&timer_arg->count, 1) > 0) {
    defint_timer_create(get_time_ms() + 1, &defint_timer_pool_cb, timer_arg, timer);
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

  defint_timer_t defint_timer;
  struct defint_timer_arg timer_arg = {
    .pool = &pool,
    .count = ATOMIC32_INIT(TEST_SIZE / 2),
  };
  defint_timer_create(get_time_ms() + 1, &defint_timer_pool_cb, &timer_arg, &defint_timer);

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
