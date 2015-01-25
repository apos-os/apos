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
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/signal/signal.h"
#include "memory/memory.h"
#include "proc/scheduler.h"

static kthread_t g_idle_thread = 0;
static kthread_queue_t g_run_queue;

static void* idle_thread_body(void* arg) {
  while(1) {
    kthread_current_thread()->state = KTHREAD_PENDING;
    scheduler_yield_no_reschedule();
  }
  return 0;
}

// TODO(aoates): add test for interrupts/idle loop.

void scheduler_init() {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_queue_init(&g_run_queue);

  // Make the idle thread.
  int ret = kthread_create(&g_idle_thread, &idle_thread_body, 0);
  KASSERT(ret == 0);
  POP_INTERRUPTS();
}

void scheduler_make_runnable(kthread_t thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_queue_push(&g_run_queue, thread);
  POP_INTERRUPTS();
}

void scheduler_interrupt_thread(kthread_t thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  if (thread->queue && thread->queue != &g_run_queue && thread->interruptable) {
    KASSERT_DBG(thread->state == KTHREAD_PENDING);
    KASSERT_DBG(kthread_current_thread()->queue == 0x0);

    kthread_queue_remove(thread);
    thread->interrupted = true;
    scheduler_make_runnable(thread);
  }
  POP_INTERRUPTS();
}

void scheduler_yield() {
  PUSH_AND_DISABLE_INTERRUPTS();
  scheduler_wait_on(&g_run_queue);
  POP_INTERRUPTS();
}

void scheduler_yield_no_reschedule() {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* new_thread = kthread_queue_pop(&g_run_queue);
  if (!new_thread) {
    new_thread = g_idle_thread;
  }
  kthread_switch(new_thread);
  POP_INTERRUPTS();
}


static int scheduler_wait_on_internal(kthread_queue_t* queue,
                                      int interruptable) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_t current = kthread_current_thread();

  if (interruptable) {
    const sigset_t dispatchable = proc_dispatchable_signals();
    if (!ksigisemptyset(&dispatchable)) {
      current->interrupted = 1;
      POP_INTERRUPTS();
      return SWAIT_INTERRUPTED;
    }
  }

  current->state = KTHREAD_PENDING;
  current->interruptable = interruptable;
  current->interrupted = 0;
  kthread_queue_push(queue, current);
  scheduler_yield_no_reschedule();
  int result = current->interrupted;
  POP_INTERRUPTS();

  return result;
}

void scheduler_wait_on(kthread_queue_t* queue) {
  int result = scheduler_wait_on_internal(queue, 0);
  KASSERT_DBG(result == 0);
}

int scheduler_wait_on_interruptable(kthread_queue_t* queue) {
  return scheduler_wait_on_internal(queue, 1);
}

void scheduler_wake_one(kthread_queue_t* queue) {
  if (!kthread_queue_empty(queue)) {
    scheduler_make_runnable(kthread_queue_pop(queue));
  }
}

void scheduler_wake_all(kthread_queue_t* queue) {
  while (!kthread_queue_empty(queue)) {
    scheduler_make_runnable(kthread_queue_pop(queue));
  }
}
