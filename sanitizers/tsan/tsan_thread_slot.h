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

#ifndef APOO_SANITIZERS_TSAN_TSAN_THREAD_SLOT_H
#define APOO_SANITIZERS_TSAN_TSAN_THREAD_SLOT_H

#include "dev/timer.h"
#include "proc/kthread-internal.h"
#include "proc/kthread.h"
#include "sanitizers/tsan/internal_types.h"
#include "sanitizers/tsan/tsan_event.h"

// A single thread slot.  When a thread is destroyed, the slot is not
// immediately cleaned up --- its log data is kept to allow tracing races that
// occur after the thread has exited.
typedef struct {
  kthread_t thread;  // Slot's current thread, or NULL.
  kthread_id_t thread_id;  // Thread ID of the thread that is/was in this slot.

  // Latest epoch for this slot (survives across reuse).  Not relevant except at
  // thread assignment.
  tsan_epoch_t epoch;

  // When the slot was last used (for LRU replacement).
  apos_ms_t last_used;

  // Event log for the current thread in this slot.
  tsan_event_log_t log;
} tsan_tslot_t;

#endif
