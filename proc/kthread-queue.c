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
#include "proc/kthread-queue.h"

#include "common/kassert.h"
#include "proc/kthread-internal.h"
#include "proc/raw_spinlock.h"
#include "proc/spinlock.h"
#include "sanitizers/tsan/spinlock_core.h"

void kthread_queue_init(kthread_queue_t* lst) {
  raw_spin_ctor(&lst->spin);
  lst->spin = RAW_SPIN_INIT;
  lst->head = lst->tail = 0x0;
}

// Inserts the node B into the linked list right after A.
TSAN_CORE_FN
static void kthread_queue_insert(kthread_data_t* A, kthread_data_t* B) {
  B->next = A->next;
  B->prev = A;
  if (A->next) {
    A->next->prev = B;
  }
  A->next = B;
}

void kthread_queue_push(kthread_queue_t* lst, kthread_data_t* thread) {
  kspin_lock_int(&thread->spin);
  raw_spin_lock(&lst->spin);
  kthread_queue_push_locked(lst, thread);
  raw_spin_unlock(&lst->spin);
  kspin_unlock_int(&thread->spin);
}

// This is TSAN_CORE_FN because it's called from scheduler_yield_no_reschedule()
// with a TSAN-core-only instrumented lock.
TSAN_CORE_FN
void kthread_queue_push_locked(kthread_queue_t* lst, kthread_data_t* thread) {
  kspin_assert_is_held_int(&thread->spin);
  raw_spin_assert_held(&lst->spin);
  KASSERT(thread->prev == 0);
  KASSERT(thread->next == 0);
  KASSERT(thread->queue == NULL);

  if (!lst->head) {
    KASSERT(lst->tail == 0x0);
    lst->head = lst->tail = thread;
    thread->prev = thread->next = 0x0;
  } else {
    if (lst->tail->prev) {
      KASSERT(lst->tail->prev->next == lst->tail);
    }
    kthread_queue_insert(lst->tail, thread);
    lst->tail = thread;
  }
  thread->queue = lst;
}

void kthread_queue_remove(kthread_t thread) {
  kspin_lock_int(&thread->spin);
  kthread_queue_t* q = thread->queue;
  raw_spin_lock(&q->spin);
  kthread_queue_remove_locked(q, thread);
  raw_spin_unlock(&q->spin);
  kspin_unlock_int(&thread->spin);
}

// TSAN_CORE_FN for the same reason as above.
TSAN_CORE_FN
void kthread_queue_remove_locked(kthread_queue_t* q, kthread_t thread) {
  kspin_assert_is_held_int(&thread->spin);
  KASSERT_DBG(thread->queue == q);
  raw_spin_assert_held(&q->spin);
  if (thread->queue->head == thread)
    thread->queue->head = thread->next;
  if (thread->queue->tail == thread)
    thread->queue->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  if (thread->next)
    thread->next->prev = thread->prev;
  thread->prev = thread->next = 0x0;
  thread->queue = NULL;
}

int kthread_queue_empty(kthread_queue_t* lst) {
  raw_spin_lock(&lst->spin);
  int result = kthread_queue_empty_locked(lst);
  raw_spin_unlock(&lst->spin);
  return result;
}

TSAN_CORE_FN
int kthread_queue_empty_locked(kthread_queue_t* lst) {
  return lst->head == 0x0;
}
