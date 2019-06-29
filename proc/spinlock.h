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
#include "proc/kthread-internal.h"

// TODO(aoates): define a proper spinlock when SMP is possible.

typedef struct {
  // The thread currently holding the spinlock, or -1 if free.
  kthread_id_t holder;

  // Interrupt state when the spinlock was locked.
  interrupt_state_t int_state;
} kspinlock_t;

extern const kspinlock_t KSPINLOCK_INIT;

// Lock the given spinlock.  In a non-SMP environment, simply disables
// preemption.  Threads must not block while holding a spinlock.
void kspin_lock(kspinlock_t* l);

// Unlock the spinlock.
void kspin_unlock(kspinlock_t* l);

// As above, but also disables interrupts.  Use this for code that needs to
// coordinate with interrupt handlers.
void kspin_lock_int(kspinlock_t* l);
void kspin_unlock_int(kspinlock_t* l);

#endif
