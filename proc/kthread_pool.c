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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread_pool.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"

static void* worker_func(void* arg) {
  kthread_pool_t* pool = (kthread_pool_t*)arg;
  while (1) {
    kspin_lock(&pool->spin);
    while (pool->queue_head == 0x0 && pool->running) {
      scheduler_wait_on_splocked(&pool->wait_queue, -1, &pool->spin);
    }

    if (pool->queue_head == 0x0) {
      KASSERT_DBG(!pool->running);
      kspin_unlock(&pool->spin);
      break;
    }

    kthread_pool_item_t* item = pool->queue_head;
    pool->queue_head = pool->queue_head->next;
    if (!pool->queue_head) {
      KASSERT(pool->queue_tail == item);
      pool->queue_tail = 0x0;
    }
    kspin_unlock(&pool->spin);

    item->cb(item->arg);
    kfree(item);
  }
  return 0x0;
}

int kthread_pool_init(kthread_pool_t* pool, int size) {
  kspin_constructor(&pool->spin);
  pool->spin = KSPINLOCK_NORMAL_INIT;
  pool->running = true;
  pool->size = size;
  pool->threads = (kthread_t*)kmalloc(sizeof(kthread_t) * size);
  if (!pool->threads) {
    return -ENOMEM;
  }

  pool->queue_head = pool->queue_tail = 0x0;
  kthread_queue_init(&pool->wait_queue);

  // Create all the threads.
  for (int i = 0; i < size; ++i) {
    if (kthread_create(&pool->threads[i], &worker_func, pool)) {
      // Note: we'll leak resources here (for all the previous threads we
      // already created).
      klogfm(KL_PROC, WARNING, "error creating one of the threads in a kthraed_pool\n");
      kfree(pool->threads);
      return -ENOMEM;
    }
  }

  for (int i = 0; i < size; ++i) {
    scheduler_make_runnable(pool->threads[i]);
  }
  return 0;
}

void kthread_pool_destroy(kthread_pool_t* pool) {
  KASSERT(pool->size > 0);
  kspin_lock(&pool->spin);
  KASSERT(pool->running);
  pool->running = false;
  scheduler_wake_all(&pool->wait_queue);
  kspin_unlock(&pool->spin);
  for (int i = 0; i < pool->size; ++i)
    kthread_join(pool->threads[i]);
  kspin_destructor(&pool->spin);
  KASSERT(pool->queue_head == NULL);
  KASSERT(pool->queue_tail == NULL);
  KASSERT(kthread_queue_empty(&pool->wait_queue));
  kfree(pool->threads);
  pool->threads = NULL;
  pool->size = 0;
}

int kthread_pool_push(kthread_pool_t* pool, kthread_pool_cb_t cb, void* arg) {
  if (!pool->threads) {
    return -EINVAL;
  }

  kthread_pool_item_t* item = (kthread_pool_item_t*)kmalloc(
      sizeof(kthread_pool_item_t));
  if (!item) {
    return -ENOMEM;
  }

  // Enqueue the new item.
  item->cb = cb;
  item->arg = arg;
  item->next = 0x0;
  {
    kspin_lock(&pool->spin);
    if (!pool->queue_head) {
      KASSERT(pool->queue_tail == 0x0);
      pool->queue_head = pool->queue_tail = item;
    } else {
      pool->queue_tail->next = item;
      pool->queue_tail = item;
    }
    scheduler_wake_one(&pool->wait_queue);
    kspin_unlock(&pool->spin);
  }
  return 0;
}
