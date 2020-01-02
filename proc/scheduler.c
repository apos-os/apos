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
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/signal/signal.h"
#include "memory/memory.h"
#include "proc/scheduler.h"

static kthread_t g_idle_thread = 0;
static kthread_queue_t g_run_queue;

static void* idle_thread_body(void* arg) {
  sched_disable_preemption();
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
    KASSERT_DBG(thread->wait_status == SWAIT_DONE);
    thread->wait_status = SWAIT_INTERRUPTED;
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

static void scheduler_timeout(void* arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* thread = arg;
  KASSERT_DBG(thread->wait_status != SWAIT_TIMEOUT);
  KASSERT_DBG(thread->interruptable);
  thread->wait_timeout_ran = true;
  if (thread->wait_status == SWAIT_DONE && thread->queue != &g_run_queue) {
    KASSERT_DBG(thread->state == KTHREAD_PENDING);
    KASSERT_DBG(kthread_current_thread()->queue == 0x0);

    kthread_queue_remove(thread);
    thread->wait_status = SWAIT_TIMEOUT;
    scheduler_make_runnable(thread);
  }
  POP_INTERRUPTS();
}

static int scheduler_wait_on_internal(kthread_queue_t* queue, int interruptable,
                                      long timeout_ms, kmutex_t* mu) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_t current = kthread_current_thread();
  // We should never be blocking if we're holding a spinlock.
  KASSERT_DBG(current->spinlocks_held == 0);

  timer_handle_t timeout_handle;
  if (interruptable) {
    const sigset_t dispatchable = proc_dispatchable_signals();
    if (!ksigisemptyset(&dispatchable)) {
      current->wait_status = SWAIT_INTERRUPTED;
      POP_INTERRUPTS();
      return SWAIT_INTERRUPTED;
    }

    if (timeout_ms > 0) {
      int result =
          register_event_timer(get_time_ms() + timeout_ms, &scheduler_timeout,
                               current, &timeout_handle);
      KASSERT_DBG(result == 0);
    }
  }

  current->state = KTHREAD_PENDING;
  current->interruptable = interruptable;
  current->wait_status = SWAIT_DONE;
  current->wait_timeout_ran = false;
  kthread_queue_push(queue, current);
  if (mu) {
    kmutex_unlock_no_yield(mu);
  }
  scheduler_yield_no_reschedule();
  int result = current->wait_status;
  if (timeout_ms > 0 && !current->wait_timeout_ran)
    cancel_event_timer(timeout_handle);
  if (mu) {
    kmutex_lock(mu);
  }
  POP_INTERRUPTS();

  return result;
}

void scheduler_wait_on(kthread_queue_t* queue) {
  int result = scheduler_wait_on_internal(queue, 0, -1, NULL);
  KASSERT_DBG(result == 0);
}

int scheduler_wait_on_interruptable(kthread_queue_t* queue, long timeout_ms) {
  return scheduler_wait_on_internal(queue, 1, timeout_ms, NULL);
}

int scheduler_wait_on_locked(kthread_queue_t* queue, long timeout_ms,
                             kmutex_t* mu) {
  return scheduler_wait_on_internal(queue, 1, timeout_ms, mu);
}

void scheduler_wait_on_locked_no_signals(kthread_queue_t* queue, kmutex_t* mu) {
  int result = scheduler_wait_on_internal(queue, 0, -1, mu);
  KASSERT_DBG(result == 0);
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

void sched_disable_preemption() {
  // TODO(aoates): use an interrupt-safe atomic here.
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_current_thread()->preemption_disables++;
  POP_INTERRUPTS();
}

void sched_restore_preemption() {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_current_thread()->preemption_disables--;
  KASSERT(kthread_current_thread()->preemption_disables >= 0);
  POP_INTERRUPTS();
}

void sched_enable_preemption_for_test() {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(kthread_current_thread()->preemption_disables == 1);
  kthread_current_thread()->preemption_disables = 0;
  POP_INTERRUPTS();
}

void sched_tick() {
  // TODO(aoates): move g_run_queue short-circuit into scheduler_yield() after
  // verifying it won't break any tests.
  if (kthread_current_thread()->preemption_disables == 0 &&
      !kthread_queue_empty(&g_run_queue)) {
    scheduler_yield();
  }
}
