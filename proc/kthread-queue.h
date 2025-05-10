// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_PROC_KTHREAD_QUEUE_H
#define APOO_PROC_KTHREAD_QUEUE_H

#include "proc/kthread.h"
#include "proc/raw_spinlock.h"
#include "proc/thread_annotations.h"

// Thread queues are simple linked lists of threads, which can be pushed on the
// back and popped from the front.  A given thread can only be on a single
// thread queue (or no thread queues) at once --- trying to enqueue a thread on
// multiple queues will result in a panic.
typedef struct {
  raw_spinlock_t spin;
  kthread_t head GUARDED_BY(&spin);
  kthread_t tail GUARDED_BY(&spin);
} kthread_queue_t;

// Initialze a thread queue.
void kthread_queue_init(kthread_queue_t* queue);

// Returns 1 if the given thread queue is empty.
int kthread_queue_empty(kthread_queue_t* queue) EXCLUDES(queue->spin);
int kthread_queue_empty_locked(kthread_queue_t* queue) REQUIRES(queue->spin);

// Enqueue a thread on the back of the given thread queue.
void kthread_queue_push(kthread_queue_t* queue, kthread_t thread)
    EXCLUDES(queue->spin);  // EXCLUDES(thread->spin)
void kthread_queue_push_locked(kthread_queue_t* queue, kthread_t thread)
    REQUIRES(queue->spin);  // REQUIRES(thread->spin)

// Removes the given thread from the list its on.
void kthread_queue_remove(kthread_t thread);  // EXCLUDES(thread->queue->spin)
void kthread_queue_remove_locked(kthread_queue_t* q, kthread_t thread)
    REQUIRES(q->spin);  // REQUIRES(thread->spin)

#endif
