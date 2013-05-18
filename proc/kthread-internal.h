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

#include <stdint.h>

#include "dev/interrupts.h"
#include "memory/memory.h"
#include "proc/kthread.h"

#define KTHREAD_RUNNING 0 // Currently running.
#define KTHREAD_PENDING 1 // Waiting on a run queue of some sort.
#define KTHREAD_DONE    2 // Finished.
#define KTHREAD_DESTROYED 3 // Destroyed.  Should never be seen.

struct process;
typedef struct process process_t;

// NOTE: if you update this structure, make sure you update kthread_asm.s as
// well.
struct kthread_data {
  uint32_t id;
  uint32_t state;
  uint32_t esp;  // KTHREAD_T_ESP in kthread_asm.s
  page_dir_ptr_t page_directory;  // KTHREAD_T_PAGE_DIRECTORY in kthread_asm.s
  void* retval;
  struct kthread_data* prev;
  struct kthread_data* next;
  uint32_t* stack;  // The block of memory allocated for the thread's stack.
  uint32_t detached;
  kthread_queue_t join_list;  // List of thread's join()'d to this one.
  // Then number of threads blocking in kthread_join() on this thread.  This is
  // distinct from join_list, since threads may have been removed from join_list
  // but not yet scheduled (and therefore still blocking in kthread_join).
  int join_list_pending;
  process_t* process;  // The process owning this thread.
};
typedef struct kthread_data kthread_data_t;

// Destroy a thread object and clean up its storage.
//
// This should NEVER be called by clients --- threads will be automatically
// cleaned up when they exit.
void kthread_destroy(kthread_t thread);

// Return a handle to the currently running thread.
kthread_t kthread_current_thread();

// Explicitly switch execution to another thread.
void kthread_switch(kthread_t new_thread);

// Chooses a new thread off the run queue and switches to it, *without*
// rescheduling the current thread on the run queue.
//
// Used internally in kthread.c and scheduler.c.  Clients should use
// scheduler_yield() (to yield and reschedule) and scheduler_wait_on() (to wait
// on another thread queue).
void scheduler_yield_no_reschedule();

#endif
