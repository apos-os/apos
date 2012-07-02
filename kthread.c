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

#define KTHREAD_STACK_SIZE 1024 // (4 * 4096)  // 16k

// A linked list of kthreads.
typedef struct {
  struct kthread* head;
  struct kthread* tail;
} kthread_list_t;

static kthread_t* g_current_thread = 0;
static int g_next_id = 0;

static kthread_list_t g_run_queue;

// Swap context from threadA (the currently running thread) to threadB (the new
// thread).
//
// Defined in kthread_asm.s
void kthread_swap_context(kthread_t* threadA, kthread_t* threadB);

// TODO(aoates): INTERRUPTS

// Inserts the node B into the linked list right after A.
static void kthread_list_insert(kthread_t* A, kthread_t* B) {
  B->next = A->next;
  B->prev = A;
  if (A->next) {
    A->next->prev = B;
  }
  A->next = B;
}

// Push a thread onto the end of a list.
static void kthread_push_back(kthread_list_t* lst, kthread_t* thread) {
  if (!lst->head) {
    KASSERT(lst->tail == 0x0);
    lst->head = lst->tail = thread;
    thread->prev = thread->next = 0x0;
  } else {
    kthread_list_insert(lst->tail, thread);
    lst->tail = thread;
  }
}

// Pop a thread off the front of a list.
static kthread_t* kthread_pop(kthread_list_t* lst) {
  KASSERT(lst->head != 0x0);
  kthread_t* front = lst->head;
  lst->head = front->next;
  if (front->next) {
    front->next->prev = 0x0;
  } else {
    lst->tail = 0x0;
  }
  front->next = 0x0;
  return front;
}

static int kthread_empty(kthread_list_t* lst) {
  return lst->head == 0x0;
}

static void kthread_list_init(kthread_list_t* lst) {
  lst->head = lst->tail = 0x0;
}

static void kthread_trampoline(void *(*start_routine)(void*), void* arg) {
  start_routine(arg);
  kthread_exit(0);
  // Should never get here.
  KASSERT(0);
}

void kthread_init() {
  KASSERT(g_current_thread == 0);

  kthread_t* first = (kthread_t*)kmalloc(sizeof(kthread_t));
  KASSERT(first != 0x0);
  first->active = 1;
  first->esp = 0;
  first->id = g_next_id++;

  kthread_list_init(&g_run_queue);
  g_current_thread = first;
}

int kthread_create(kthread_t *thread, void *(*start_routine)(void*),
                   void *arg) {
  thread->id = g_next_id++;
  thread->active = 0;
  thread->esp = 0;
  thread->retval = 0x0;

  // Allocate a stack for the thread.
  uint32_t* stack = (uint32_t*)kmalloc(KTHREAD_STACK_SIZE);
  KASSERT(stack != 0x0);
  thread->stack = stack;
  stack = (uint32_t*)((uint8_t*)stack + KTHREAD_STACK_SIZE - 4);

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
  // TODO(aoates): this isn't quite correct, we don't take into account what
  // swap_context might have done to the stack!
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

void kthread_yield() {
  if (kthread_empty(&g_run_queue)) {
    return;
  }

  uint32_t my_id = g_current_thread->id;

  kthread_t* old_thread = g_current_thread;
  kthread_t* new_thread = kthread_pop(&g_run_queue);
  g_current_thread = new_thread;
  kthread_push_back(&g_run_queue, old_thread);
  kthread_swap_context(old_thread, new_thread);

  // Verify that we're back on the proper stack!
  KASSERT(g_current_thread->id == my_id);
}

void kthread_exit(void* x) {
  // kthread_exit is basically the same as kthread_yield, but we don't put
  // ourselves back on the run queue.
  g_current_thread->retval = x;

  // TODO(aoates): we need an idle thread to run here!
  KASSERT(!kthread_empty(&g_run_queue));
  kthread_t* old_thread = g_current_thread;
  kthread_t* new_thread = kthread_pop(&g_run_queue);
  g_current_thread = new_thread;
  kthread_swap_context(old_thread, new_thread);
  // Never get here!
  KASSERT(0);
}


//static void swap_context(kthread_t* target) {
//  kthread_swap_cont
//  g_current_thread->active = 0;
//  // interrupts!
//  __asm__ __volatile__(
//      "push %%eax\n\t"
//      "push %%ecx\n\t"
//      "push %%edx\n\t"
//      "push %%ebx\n\t"
//      "push %%ebp\n\t"
//      "push %%esi\n\t"
//      "push %%edi\n\t"
//      "mov %%esp, %0\n\t"
//      "mov %1, %%esp\n\t"
//      "pop %%edi\n\t"
//      "pop %%esi\n\t"
//      "pop %%ebp\n\t"
//      "pop %%ebx\n\t"
//      "pop %%edx\n\t"
//      "pop %%ecx\n\t"
//      "pop %%eax\n\t"
//      : "=m"(g_current_thread->esp) : "m"(target->esp));
//  // assert(cs == 0x08)
//  // assert(ds == 0x10)
//  g_current_thread = target;
//  g_current_thread->active = 1;
//}
