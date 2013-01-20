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

// A pool of kthreads, onto which callbacks can be pushed.  Callbacks will be
// run in FIFO order on the threads.
//
// Note: since the kernel is non-preemptive, if the callbacks don't block (e.g.
// on I/O), then there is no advantage in using more than one thread in the
// pool.
#ifndef APOO_PROC_KTHREAD_POOL_H
#define APOO_PROC_KTHREAD_POOL_H

#include "proc/kthread.h"

struct kthread_pool;
typedef struct kthread_pool kthread_pool_t;

// A callback to be run on the threadpool.
typedef void (*kthread_pool_cb_t)(void* arg);

// Initialize a threadpool and set it to the given size.
//
// Returns -errno on failure.
int kthread_pool_init(kthread_pool_t* pool, int size);

// Push a callback (and args) onto the thread pool's queue.  When a worker
// thread is available, it will invoke the callback on that thread.
//
// Note: this is interrupt-safe (that is, it is safe to invoke this from
// both interrupt and non-interrupt contexts without additional protection).  It
// will not block.
//
// Returns -errno on failure.
int kthread_pool_push(kthread_pool_t* pool, kthread_pool_cb_t cb, void* arg);

// A single item of work for the thread pool.
struct kthread_pool_item {
  kthread_pool_cb_t cb;
  void* arg;
  struct kthread_pool_item* next;
};
typedef struct kthread_pool_item kthread_pool_item_t;

struct kthread_pool {
  int size;
  kthread_t* threads;
  kthread_pool_item_t* queue_head;
  kthread_pool_item_t* queue_tail;
  kthread_queue_t wait_queue;
};

#endif
