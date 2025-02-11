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

// Internal data structures used by the threading and scheduler packages.
#ifndef APOO_KTHREAD_INTERNAL_H
#define APOO_KTHREAD_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "arch/proc/kthread-context.h"
#include "arch/proc/kthread-stack.h"
#include "common/list.h"
#include "common/types.h"
#include "memory/memory.h"
#include "proc/kthread.h"
#include "user/include/apos/posix_signal.h"
#include "syscall/context.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_thread.h"
#endif

typedef enum {
  KTHREAD_RUNNING = 0,    // Currently running.
  KTHREAD_PENDING = 1,    // Waiting on a run queue of some sort.
  KTHREAD_DONE = 2,       // Finished.
  KTHREAD_DESTROYED = 3,  // Destroyed.  Should never be seen.
} kthread_state_t;

struct process;
typedef struct process process_t;

struct kthread_data {
  kthread_id_t id;
  kthread_state_t state;
  kthread_arch_context_t context;
  void* retval;
  struct kthread_data* prev;
  struct kthread_data* next;
  kthread_queue_t* queue;  // The queue we're waiting on, if any.
  addr_t* stack;  // The block of memory allocated for the thread's stack.
  addrdiff_t stacklen;
  bool detached;
  bool runnable;  // Crude way to disable threads for tests.
  kthread_queue_t join_list;  // List of thread's join()'d to this one.
  // Then number of threads blocking in kthread_join() on this thread.  This is
  // distinct from join_list, since threads may have been removed from join_list
  // but not yet scheduled (and therefore still blocking in kthread_join).
  int join_list_pending;
  process_t* process;  // The process owning this thread.

  // The current signal mask (i.e. the signals blocked in this thread).
  ksigset_t signal_mask;

  // The set of signals assigned to this thread for handling.
  ksigset_t assigned_signals;

  // Context for the currently-executing syscall, if any.
  syscall_context_t syscall_ctx;

  // Whether or not the thread can be interrupted (e.g. by a signal) if it's
  // blocked on a queue.
  bool interruptable;

  // SWAIT_INTERRUPTED or SWAIT_TIMEOUT if the thread was woken up from an
  // interruptable wait and forced onto the run queue, by a signal or timeout,
  // respectively.
  unsigned char wait_status;

  // Whether or not the wait timeout fired, regardless of if it was interrupted
  // first.
  bool wait_timeout_ran;

  // Current preemption-disabled counter.  If zero, preemption is allowed.
  int preemption_disables;

  // How many spinlocks we're holding, for bug-catching.
  int spinlocks_held;

  // Link on the global thread list.
  // TODO(aoates): once we support multiple threads per process, consider using
  // a per-process thread list rather than a global one.
  list_link_t all_threads_link;

  // Link on the per-process thread list.
  list_link_t proc_threads_link;

  // How many levels of interrupt are currently being processed (0 <= n <= 2).
  // Arch code must maintain this --- incrementing on interrupt start,
  // decrementing on finish, and setting to zero when user mode is entered.
  int interrupt_level;

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  // List of currently-held mutexes.
  list_t mutexes_held;
#endif

#if ENABLE_TSAN
  tsan_thread_data_t tsan;
  bool legacy_interrupt_sync;
#endif
};
typedef struct kthread_data kthread_data_t;

// Destroy a thread object and clean up its storage.
//
// This should NEVER be called by clients --- threads will be automatically
// cleaned up when they exit.
void kthread_destroy(kthread_t thread);

// Return a handle to the currently running thread.
kthread_t kthread_current_thread(void);

// Explicitly switch execution to another thread.
void kthread_switch(kthread_t new_thread);

// Chooses a new thread off the run queue and switches to it, *without*
// rescheduling the current thread on the run queue.
//
// Used internally in kthread.c and scheduler.c.  Clients should use
// scheduler_yield() (to yield and reschedule) and scheduler_wait_on() (to wait
// on another thread queue).
void scheduler_yield_no_reschedule(void);

// Helper function to reset current interrupt level to zero.
void kthread_reset_interrupt_level(void);

#endif
