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

#ifndef APOO_PROC_SPINLOCK_H
#define APOO_PROC_SPINLOCK_H

#include "arch/dev/interrupts.h"
#include "proc/defint.h"
#include "proc/kthread-internal.h"

// TODO(aoates): define a proper spinlock when SMP is possible.

typedef enum {
  // A spinlock that disables preemption and deferred interrupts.  Must not be
  // used from an interrupt context.
  SPINLOCK_NORMAL,

  // A spinlock that also disables interrupts (and therefore can be used from an
  // interrupt context, and to protect state shared between normal code and
  // interrupts).
  SPINLOCK_INTERRUPT_SAFE,
} kspinlock_type_t;

typedef struct {
  kspinlock_type_t type;

  // The thread currently holding the spinlock, or -1 if free.
  kthread_id_t holder;

  // Defint state when the spinlock was locked.
  defint_state_t defint_state;

  // Interrupt state when the spinlock was locked.
  interrupt_state_t int_state;
} kspinlock_t;

extern const kspinlock_t KSPINLOCK_NORMAL_INIT;
extern const kspinlock_t KSPINLOCK_INTERRUPT_SAFE_INIT;

// Lock the given spinlock.  In a non-SMP environment, simply disables
// preemption, defints, and optionally interrupts (depending on the type).
// Threads must not block while holding a spinlock.
void kspin_lock(kspinlock_t* l);

// Unlock the spinlock.
void kspin_unlock(kspinlock_t* l);

// Returns true if the spinlock is held by the current thread.
bool kspin_is_held(const kspinlock_t* l);

#endif
