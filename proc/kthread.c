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

#include "arch/proc/kthread.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "memory/memory.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"

static kthread_data_t* g_current_thread = 0;
static int g_next_id = 0;

// A queue of threads that have exited and we can clean up.
static kthread_queue_t g_reap_queue;

static void kthread_init_kthread(kthread_data_t* t) {
  t->state = KTHREAD_PENDING;
  t->id = 0;
  t->retval = 0x0;
  t->prev = t->next = 0x0;
  t->queue = 0x0;
  t->stack = 0x0;
  t->detached = false;
  kthread_queue_init(&t->join_list);
  t->join_list_pending = 0;
  t->process = 0x0;
  ksigemptyset(&t->signal_mask);
  ksigemptyset(&t->assigned_signals);
  t->interruptable = false;
  t->interrupted = false;
}

static void kthread_trampoline(void *(*start_routine)(void*), void* arg) {
  void* retval = start_routine(arg);
  kthread_exit(retval);
  // Should never get here.
  KASSERT(0);
}

void kthread_init() {
  kthread_arch_init();

  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_current_thread == 0);

  kthread_data_t* first = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  KASSERT(first != 0x0);
  kthread_init_kthread(first);
  first->state = KTHREAD_RUNNING;
  first->id = g_next_id++;
  first->stack = (addr_t*)get_global_meminfo()->kernel_stack_base;

  KASSERT_DBG((addr_t)(&first) < (addr_t)first->stack + KTHREAD_STACK_SIZE);

  kthread_queue_init(&g_reap_queue);

  g_current_thread = first;
  kthread_arch_set_current_thread(first);
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
  thread->retval = 0x0;
  ksigemptyset(&thread->signal_mask);

  // TODO(aoates): add the thread to the parent process's thread list, once
  // we support multiple threads per process.
  thread->process = proc_current();

  // Allocate a stack for the thread.
  addr_t* stack = (addr_t*)kmalloc_aligned(KTHREAD_STACK_SIZE, PAGE_SIZE);
  KASSERT(stack != 0x0);

  // Touch each page of the stack to make sure it's paged in.  If we don't do
  // this, when we try to use the stack, we'll cause a page fault, which will in
  // turn cause a double (then triple) fault when IT tries to use the stack.
  for (addr_t i = 0; i < KTHREAD_STACK_SIZE / PAGE_SIZE; ++i) {
    *((uint8_t*)stack + i * PAGE_SIZE) = 0xAA;
  }
  *((uint8_t*)stack + KTHREAD_STACK_SIZE - 1) = 0xAA;

  thread->stack = stack;
  kthread_arch_init_thread(thread, kthread_trampoline, start_routine, arg);
  POP_INTERRUPTS();
  return 0;
}

void kthread_destroy(kthread_t thread) {
  // Write gargbage to crash anyone that tries to use the thread later.
  kmemset(&thread->context, 0xAB, sizeof(kthread_arch_context_t));
  thread->state = KTHREAD_DESTROYED;
  if (thread->stack) {
    kfree(thread->stack);
    thread->stack = 0x0;
  }

  // If we're in debug mode, leave the thread body around to we can die if we
  // try to use it later.
  if(!ENABLE_KERNEL_SAFETY_NETS) {
    kfree(thread);
  }
}

void kthread_detach(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  KASSERT(!thread->detached);
  KASSERT(thread->join_list_pending == 0);
  thread->detached = true;
}

void* kthread_join(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  KASSERT(thread->state == KTHREAD_PENDING ||
          thread->state == KTHREAD_DONE);
  KASSERT(!thread->detached);

  if (thread->state != KTHREAD_DONE) {
    thread->join_list_pending++;
    scheduler_wait_on(&thread->join_list);
    thread->join_list_pending--;
  }
  KASSERT(thread->state == KTHREAD_DONE);
  void* retval = thread->retval;
  // If we're last, clean up after the thread.
  if (thread->join_list_pending == 0) {
    kthread_destroy(thread);
  }
  return retval;
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

  if (g_current_thread->detached) {
    kthread_queue_push(&g_reap_queue, g_current_thread);
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
  kthread_arch_set_current_thread(g_current_thread);
  new_thread->state = KTHREAD_RUNNING;

  // If either the old or new thread isn't owned by a process (as with some
  // kernel threads), either unconditionally switch to the new thread's address
  // space, or continue executing in whatever address space we're already in.
  // TODO(aoates): should we really allow orphan threads like this?  Or should
  // we require all such threads to be tied to the root process?  It's a little
  // weird that these threads can end up executing in arbitrary address spaces.
  const page_dir_ptr_t old_pd =
      (old_thread->process ? old_thread->process->page_directory : 0x0);
  const page_dir_ptr_t new_pd =
      (new_thread->process ? new_thread->process->page_directory : old_pd);
  if (new_thread->process) {
    proc_set_current(new_thread->process);
  }
  kthread_arch_swap_context(old_thread, new_thread, old_pd, new_pd);

  // Verify that we're back on the proper stack!
  KASSERT(g_current_thread->id == my_id);

  // Clean up any thread stacks waiting to be reaped.
  kthread_t t = kthread_queue_pop(&g_reap_queue);
  while (t) {
    kthread_destroy(t);
    t = kthread_queue_pop(&g_reap_queue);
  }

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

void kmutex_init(kmutex_t* m) {
  m->locked = 0;
  m->holder = 0x0;
  kthread_queue_init(&m->wait_queue);
}

void kmutex_lock(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  if (m->locked) {
    // Mutexes are non-reentrant, so this would deadlock.
    KASSERT_MSG(m->holder != kthread_current_thread(),
                "Mutexs are non-reentrant: cannot lock mutex already held by "
                "the current thread!");
    scheduler_wait_on(&m->wait_queue);
  } else {
    m->locked = 1;
  }
  KASSERT(m->locked == 1);
  m->holder = kthread_current_thread();
  POP_INTERRUPTS();
}

void kmutex_unlock(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();

  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  if (!kthread_queue_empty(&m->wait_queue)) {
    kthread_t next_holder = kthread_queue_pop(&m->wait_queue);
    scheduler_make_runnable(next_holder);
    scheduler_yield();
  } else {
    m->locked = 0;
    m->holder = 0x0;
  }
  POP_INTERRUPTS();
}

int kmutex_is_locked(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int is_locked = m->locked;
  POP_INTERRUPTS();
  return is_locked;
}

void kmutex_assert_is_held(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  POP_INTERRUPTS();
}

void kmutex_assert_is_not_held(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->holder != kthread_current_thread());
  POP_INTERRUPTS();
}
