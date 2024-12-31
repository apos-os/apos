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
#include "proc/kthread-internal.h"
#include "sanitizers/tsan/internal_types.h"

// TODO(tsan): use an atomic.
extern bool g_tsan_init;

static ALWAYS_INLINE void tsan_epoch_inc(tsan_epoch_t* epoch) {
  KASSERT(*epoch < TSAN_EPOCH_MAX);
  (*epoch)++;
}

static ALWAYS_INLINE void tsan_thread_epoch_inc(kthread_t thread) {
  tsan_epoch_inc(&thread->tsan.clock.ts[thread->tsan.sid]);
}

#endif
