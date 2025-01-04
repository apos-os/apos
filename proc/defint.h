// Copyright 2019 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_PROC_DEFINT_H
#define APOO_PROC_DEFINT_H

#include <stdbool.h>

#include "common/debug.h"

// Deferred interrupts are bits of code that are allowed to preempt other kernel
// code (which is otherwise not done) but run with interrupts enabled.  This
// allows drivers to minimize the amount of work done in an actual interrupt
// context (with interrupts disabled) while still processing them in a timely
// manner.
//
// Rules for deferred interrupt code:
//  - must be interruptable
//  - must not take any locks
//  - should avoid blocking operations
//  - shared state must be protected
//
// Deferred interrupts are not reentrant (if a deferred interrupt is scheduled
// while another is running, it won't run until the first one finishes).
//
// Any code that runs with interrupts disabled is guaranteed not to be preempted
// by a defint (that is, interrupt-safe code is also defint-safe code).  Defint
// state (enabled or disabled) is per-thread, same as interrupts.  A thread
// protecting state with defint_disable() must not block or yield unless the
// state is valid.

// Function signature for a defint.
typedef void (*defint_func_t)(void*);

typedef bool defint_state_t;

// Schedule a deferred interrupt.  Should generally be called from an interrupt
// context.  The deferred interrupt will be run as soon as the current interrupt
// is finished, or (if defints are disabled) when they are reenabled.
//
// Interrupt-safe.
void defint_schedule(defint_func_t f, void* arg);

// Returns the current defint state.
defint_state_t defint_state(void);

// Enables or disables deferred interrupts.  If enabling, any pending defints
// will be run immediately in the current thread's context.
//
// Most code should use DEFINT_PUSH_AND_DISABLE() and DEFINT_POP() below.
defint_state_t defint_set_state(defint_state_t s);

// Process any enqueued defints.  Will not process if interrupts are currently
// disabled unless |force| is true.  Defints are run with interrupts enabled, so
// |force| should only be set if it is safe to enable interrupts.
void defint_process_queued(bool force);

#if ENABLE_KERNEL_SAFETY_NETS
// If safety nets are enabled, verify that defint state is restorted properly at
// the end of the code block where they're disabled.
void _defint_disabled_die(void);
static inline void _defint_cleanup_verify(defint_state_t* saved) {
  if (*saved != defint_state()) {
    _defint_disabled_die();
  }
}

#define DEFINT_PUSH_AND_DISABLE()                                       \
  bool _defint_state __attribute__((cleanup(_defint_cleanup_verify))) = \
      defint_set_state(false)

#else  // ENABLE_KERNEL_SAFETY_NETS

#define DEFINT_PUSH_AND_DISABLE() bool _defint_state = defint_set_state(false)

#endif  // ENABLE_KERNEL_SAFETY_NETS

#define DEFINT_POP() defint_set_state(_defint_state)

typedef enum {
  DEFINT_NONE,        // We're not running a defint.
  DEFINT_THREAD_CTX,  // We're running a defint triggered synchronously from a
                      // thread context.
  DEFINT_INTERRUPT_CTX,  // We're running a defint triggered from an interrupt
                         // context
} defint_running_t;

// Return whether we're running a defint and if so, how it was triggered.
defint_running_t defint_running_state(void);

#endif
