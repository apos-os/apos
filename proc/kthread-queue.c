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

void kthread_queue_init(kthread_queue_t* lst) {
  lst->head = lst->tail = 0x0;
}

// Inserts the node B into the linked list right after A.
static void kthread_queue_insert(kthread_data_t* A, kthread_data_t* B) {
  B->next = A->next;
  B->prev = A;
  if (A->next) {
    A->next->prev = B;
  }
  A->next = B;
}

// Push a thread onto the end of a list.
void kthread_queue_push(kthread_queue_t* lst, kthread_data_t* thread) {
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

// Pop a thread off the front of a list.
kthread_t kthread_queue_pop(kthread_queue_t* lst) {
  if (!lst->head) {
    return lst->head;
  }
  kthread_data_t* front = lst->head;
  lst->head = front->next;
  if (front->next) {
    KASSERT(front->next->prev == front);
    front->next->prev = 0x0;
  } else {
    lst->tail = 0x0;
  }
  front->next = 0x0;
  KASSERT(front->next == 0x0 && front->prev == 0x0);
  KASSERT(front->queue == lst);
  front->queue = NULL;
  return front;
}

void kthread_queue_remove(kthread_t thread) {
  KASSERT_DBG(thread->queue != NULL);
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
  return lst->head == 0x0;
}

