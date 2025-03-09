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

// A defint-based timer.
#ifndef APOO_PROC_DEFINT_TIMER_H
#define APOO_PROC_DEFINT_TIMER_H

#include "common/list.h"
#include "dev/timer.h"
#include "proc/spinlock.h"

// For thread safety annotations only.
extern kspinlock_t g_defint_timer_lock;

struct defint_timer;
typedef struct defint_timer defint_timer_t;

// Defint timer callback.
typedef void (*defint_timer_cb_t)(defint_timer_t* timer, void* arg);

// Opaque type.
struct defint_timer {
  apos_ms_t deadline;    // const after construction.
  defint_timer_cb_t cb;  // const after construction.
  void* cb_arg;          // const after construction.

  bool started_run GUARDED_BY(g_defint_timer_lock);
  list_link_t link GUARDED_BY(g_defint_timer_lock);;
};

// Creates a defint timer that will run the given callback after the trigger
// time from a defint context.  The caller MUST ensure the given handle lives
// until the timer fires or is cancelled.  The timer object can be deleted in
// the callback only if the caller ensures there will not be a concurrent
// cancellation.
void defint_timer_create(apos_ms_t deadline_ms, defint_timer_cb_t cb, void* arg,
                         defint_timer_t* handle);

// Cancels the given defint timer if it has not run yet.  If it is currently
// running, or has already run, this is a no-op.  Returns true if the timer is
// cancelled, false if not (concurrently running or already run).
//
// Note: the caller MUST ensure the timer object lives long enough for all
// possible callbacks and cancellations to finish.  Because there is no way to
// block until a timer is done running, this means any cancellable timers should
// be used with a refcount.
bool defint_timer_cancel(defint_timer_t* handle);

// Run from an interrupt context to schedule any timers that are due.
void defint_timer_run(apos_ms_t now);

#endif
