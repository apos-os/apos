// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SANITIZERS_TSAN_INTERNAL_H
#define APOO_SANITIZERS_TSAN_INTERNAL_H

#include "common/attributes.h"
#include "common/kassert.h"
#include "common/linker_symbols.h"
#include "proc/kthread-internal.h"
#include "sanitizers/tsan/internal_types.h"
#include "sanitizers/tsan/tsan_event.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_thread_slot.h"

typedef unsigned long uptr;

extern int g_tsan_init;  // Don't read directly.
static inline ALWAYS_INLINE bool tsan_initialized(void) {
  return __atomic_load_n(&g_tsan_init, ATOMIC_ACQUIRE);
}

static ALWAYS_INLINE void tsan_epoch_inc(tsan_epoch_t* epoch) {
  KASSERT(*epoch < TSAN_EPOCH_MAX);
  (*epoch)++;
}

static ALWAYS_INLINE void tsan_thread_epoch_inc(kthread_t thread) {
  tsan_epoch_inc(&thread->tsan.clock.ts[thread->tsan.sid]);
}

void tsan_per_cpu_init(void);

// Returns true if the address is in an instrumented region.  This must be a
// dynamic check because we only map the writable portions of the kernel image
// plus the heap, not read-only data or code, which also appear in the overall
// mapped region.
static inline ALWAYS_INLINE bool tsan_is_mapped_addr(addr_t addr) {
  // N.B. this is an abstraction leak (to access
  // KERNEL_DATA_START/KERNEL_DATA_END directly), but means this can hopefully
  // be done without any memory accesses.
  return (addr >= TSAN_HEAP_START_ADDR && addr < TSAN_HEAP_END_ADDR) ||
         (addr >= (addr_t)&KERNEL_DATA_START &&
          addr < (addr_t)&KERNEL_DATA_END);
}

// Returns the current "TSAN thread."  This will be the actual current thread if
// we're executing in a thread context, or a TSAN-specific virtual thread
// otherwise.
kthread_t tsan_current_thread(void);

// Returns the log for the given thread.
tsan_event_log_t* tsan_log(kthread_t thread);

// Returns the thread slot data for the given slot ID.
tsan_tslot_t* tsan_get_tslot(tsan_sid_t sid);

// Returns the number of free thread slots (racy, for tests).
int tsan_free_thread_slots(void);

// TODO(tsan): move this into an arch header.
#define SIZE_OF_JUMP_INSTR 4
#define CALLERPC ((uptr)__builtin_return_address(0) - SIZE_OF_JUMP_INSTR)

#endif
