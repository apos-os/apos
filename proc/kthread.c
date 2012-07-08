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
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "memory.h"
#include "proc/scheduler.h"

#define KTHREAD_STACK_SIZE (4 * 4096)  // 16k

static kthread_data_t* g_current_thread = 0;
static int g_next_id = 0;

// Swap context from threadA (the currently running thread) to threadB (the new
// thread).
//
// Defined in kthread_asm.s
void kthread_swap_context(kthread_data_t* threadA, kthread_data_t* threadB);

static void kthread_init_kthread(kthread_data_t* t) {
  t->state = KTHREAD_PENDING;
  t->id = t->esp = 0;
  t->retval = 0x0;
  t->prev = t->next = 0x0;
  t->stack = 0x0;
  kthread_queue_init(&t->join_list);
  t->process = 0x0;
}

static void kthread_trampoline(void *(*start_routine)(void*), void* arg) {
  void* retval = start_routine(arg);
  kthread_exit(retval);
  // Should never get here.
  KASSERT(0);
}

void kthread_init() {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_current_thread == 0);

  kthread_data_t* first = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  KASSERT(first != 0x0);
  kthread_init_kthread(first);
  first->state = KTHREAD_RUNNING;
  first->esp = 0;
  first->id = g_next_id++;

  g_current_thread = first;
  POP_INTERRUPTS();
}

kthread_t kthread_current_thread() {
  return g_current_thread;
}

int kthread_create(kthread_t *thread_ptr, void *(*start_routine)(void*),
                   void *arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* thread = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  *thread_ptr = thread;

  kthread_init_kthread(thread);
  thread->id = g_next_id++;
  thread->state = KTHREAD_PENDING;
  thread->esp = 0;
  thread->retval = 0x0;

  // TODO(aoates): use the process from the parent thread for this thread, once
  // we support multiple threads per process.

  // Allocate a stack for the thread.
  uint32_t* stack = (uint32_t*)kmalloc(KTHREAD_STACK_SIZE);
  KASSERT(stack != 0x0);

  // Touch each page of the stack to make sure it's paged in.  If we don't do
  // this, when we try to use the stack, we'll cause a page fault, which will in
  // turn cause a double (then triple) fault when IT tries to use the stack.
  for (uint32_t i = 0; i < KTHREAD_STACK_SIZE / PAGE_SIZE; ++i) {
    *((uint8_t*)stack + i * PAGE_SIZE) = 0xAA;
  }
  *((uint8_t*)stack + KTHREAD_STACK_SIZE - 1) = 0xAA;

  thread->stack = stack;
  stack = (uint32_t*)((uint32_t)stack + KTHREAD_STACK_SIZE - 4);

  // Set up the stack.
  *(stack--) = 0xDEADDEAD;
  // Jump into the trampoline at first.  First push the args, then the eip saved
  // from the "call" to kthread_trampoline (since kthread_trampoline never
  // returns, we should never try to pop and access it).  Then push the address
  // of the start of kthread_trampoline, which swap_context will pop and jump to
  // when it calls "ret".
  *(stack--) = (uint32_t)(arg);
  *(stack--) = (uint32_t)(start_routine);
  *(stack--) = 0xDEADEADD;  // Fake saved eip.
  *(stack--) = (uint32_t)(&kthread_trampoline);

  // Set set up the stack as if we'd called swap_context().
  // First push the saved %ebp, which points to the ebp used by the 'call' to
  // swap_context -- since we jump into the trampoline (which will do it's own
  // thing with ebp), this doesn't have to be valid.
  *(stack--) = 0xDEADBADD;
  *(stack--) = 0;  // ebx
  *(stack--) = 0;  // esi
  *(stack--) = 0;  // edi

  // "push" the flags.
  uint32_t flags;
  __asm__ __volatile__ (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(flags));
  // Enable interrupts by default in the new thread.
  flags = flags | IF_FLAG;
  *(stack--) = flags;

  stack++;  // Point to last valid element.
  thread->esp = (uint32_t)stack;
  POP_INTERRUPTS();
  return 1;
}

void* kthread_join(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  if (thread->state != KTHREAD_DONE) {
    scheduler_wait_on(&thread->join_list);
    // TODO(aoates): clean up if no-one else is waiting on this thread.
  }
  KASSERT(thread->state == KTHREAD_DONE);
  return thread->retval;
}

void kthread_exit(void* x) {
  PUSH_AND_DISABLE_INTERRUPTS();
  // kthread_exit is basically the same as kthread_yield, but we don't put
  // ourselves back on the run queue.
  g_current_thread->retval = x;
  g_current_thread->state = KTHREAD_DONE;

  // Schedule all the waiting threads.
  kthread_data_t* t = kthread_queue_pop(&g_current_thread->join_list);
  while (t) {
    KASSERT(t->state == KTHREAD_PENDING);
    scheduler_make_runnable(t);
    t = kthread_queue_pop(&g_current_thread->join_list);
  }

  scheduler_yield_no_reschedule();

  // Never get here!
  KASSERT(0);
  POP_INTERRUPTS();
}

void kthread_switch(kthread_t new_thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_current_thread->state != KTHREAD_RUNNING);
  uint32_t my_id = g_current_thread->id;

  kthread_data_t* old_thread = g_current_thread;
  g_current_thread = new_thread;
  new_thread->state = KTHREAD_RUNNING;
  kthread_swap_context(old_thread, new_thread);

  // Verify that we're back on the proper stack!
  KASSERT(g_current_thread->id == my_id);
  POP_INTERRUPTS();
}

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
  return front;
}

int kthread_queue_empty(kthread_queue_t* lst) {
  return lst->head == 0x0;
}
