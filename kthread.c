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
#include "kmalloc.h"
#include "kthread.h"
#include "memory.h"

#define KTHREAD_STACK_SIZE (4 * 4096)  // 16k

struct kthread_data;

// A linked list of kthreads.
typedef struct {
  struct kthread_data* head;
  struct kthread_data* tail;
} kthread_queue_t;

#define KTHREAD_RUNNING 0 // Currently running.
#define KTHREAD_PENDING 1 // Waiting on a run queue of some sort.
#define KTHREAD_DONE    2 // Finished.

// NOTE: if you update this structure, make sure you update kthread_asm.s as
// well.
struct kthread_data {
  uint32_t id;
  uint32_t state;
  uint32_t esp;
  void* retval;
  struct kthread_data* prev;
  struct kthread_data* next;
  uint32_t* stack;  // The block of memory allocated for the thread's stack.
  kthread_queue_t join_list;  // List of thread's join()'d to this one.
};
typedef struct kthread_data kthread_data_t;

static kthread_data_t* g_current_thread = 0;
static kthread_t g_idle_thread = 0;
static int g_next_id = 0;

static kthread_queue_t g_run_queue;

// Swap context from threadA (the currently running thread) to threadB (the new
// thread).
//
// Defined in kthread_asm.s
void kthread_swap_context(kthread_data_t* threadA, kthread_data_t* threadB);

// Just like kthread_yield, but doesn't reschedule the current thread on the run
// queue.
static void kthread_yield_no_reschedule();

// TODO(aoates): INTERRUPTS

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
static void kthread_push_back(kthread_queue_t* lst, kthread_data_t* thread) {
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
static kthread_data_t* kthread_pop(kthread_queue_t* lst) {
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
  return front;
}

//static int kthread_empty(kthread_queue_t* lst) {
//  return lst->head == 0x0;
//}

static void kthread_queue_init(kthread_queue_t* lst) {
  lst->head = lst->tail = 0x0;
}

static void kthread_init_kthread(kthread_data_t* t) {
  t->state = KTHREAD_PENDING;
  t->id = t->esp = 0;
  t->retval = 0x0;
  t->prev = t->next = 0x0;
  t->stack = 0x0;
  kthread_queue_init(&t->join_list);
}

static void kthread_trampoline(void *(*start_routine)(void*), void* arg) {
  void* retval = start_routine(arg);
  kthread_exit(retval);
  // Should never get here.
  KASSERT(0);
}

static void* kthread_idle_thread_body(void* arg) {
  int iter = 0;
  while(1) {
    if (iter % 100000 == 0) {
      klogf("[idle thread]\n");
      iter = 0;
    }
    iter++;
    g_current_thread->state = KTHREAD_PENDING;
    kthread_yield_no_reschedule();
  }
  return 0;
}

void kthread_init() {
  KASSERT(g_current_thread == 0);

  kthread_data_t* first = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  KASSERT(first != 0x0);
  kthread_init_kthread(first);
  first->state = KTHREAD_RUNNING;
  first->esp = 0;
  first->id = g_next_id++;

  kthread_queue_init(&g_run_queue);
  g_current_thread = first;

  // Make the idle thread.
  int ret = kthread_create(&g_idle_thread, &kthread_idle_thread_body, 0);
  KASSERT(ret != 0);
}

int kthread_create(kthread_t *thread_ptr, void *(*start_routine)(void*),
                   void *arg) {
  kthread_data_t* thread = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  *thread_ptr = thread;

  kthread_init_kthread(thread);
  thread->id = g_next_id++;
  thread->state = KTHREAD_PENDING;
  thread->esp = 0;
  thread->retval = 0x0;

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
  *(stack--) = flags;
  // TODO(aoates): we probably need to enable interrupts in the flag manually!

  stack++;  // Point to last valid element.
  thread->esp = (uint32_t)stack;
  kthread_push_back(&g_run_queue, thread);
  return 1;
}

void* kthread_join(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  if (thread->state != KTHREAD_DONE) {
    g_current_thread->state = KTHREAD_PENDING;
    kthread_push_back(&thread->join_list, g_current_thread);
    kthread_yield_no_reschedule();
    // TODO(aoates): clean up if no-one else is waiting on this thread.
  }
  KASSERT(thread->state == KTHREAD_DONE);
  return thread->retval;
}

static void kthread_yield_no_reschedule() {
  uint32_t my_id = g_current_thread->id;

  kthread_data_t* old_thread = g_current_thread;
  kthread_data_t* new_thread = kthread_pop(&g_run_queue);
  if (!new_thread) {
    new_thread = g_idle_thread;
  }
  g_current_thread = new_thread;
  new_thread->state = KTHREAD_RUNNING;
  kthread_swap_context(old_thread, new_thread);

  // Verify that we're back on the proper stack!
  KASSERT(g_current_thread->id == my_id);
}

void kthread_yield() {
  g_current_thread->state = KTHREAD_PENDING;
  kthread_push_back(&g_run_queue, g_current_thread);
  kthread_yield_no_reschedule();
}

void kthread_exit(void* x) {
  // kthread_exit is basically the same as kthread_yield, but we don't put
  // ourselves back on the run queue.
  g_current_thread->retval = x;
  g_current_thread->state = KTHREAD_DONE;

  // Schedule all the waiting threads.
  kthread_data_t* t = kthread_pop(&g_current_thread->join_list);
  while (t) {
    KASSERT(t->state == KTHREAD_PENDING);
    kthread_push_back(&g_run_queue, t);
    t = kthread_pop(&g_current_thread->join_list);
  }

  kthread_yield_no_reschedule();

  // Never get here!
  KASSERT(0);
}
