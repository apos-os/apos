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

#ifndef APOO_SANITIZERS_TSAN_TSAN_LOCK_H
#define APOO_SANITIZERS_TSAN_TSAN_LOCK_H

#include "sanitizers/tsan/vector_clock.h"

// Per-lock TSAN state.
typedef struct {
  tsan_vc_t clock;
} tsan_lock_data_t;

// Types of mutex locks.
typedef enum {
  TSAN_LOCK = 1,
  // TODO(tsan): implement interrupt and defint special handling.
} tsan_lock_type_t;

void tsan_lock_init(tsan_lock_data_t* lock);

// Call when a thread locks a lock.
void tsan_acquire(tsan_lock_data_t* lock, tsan_lock_type_t type);

// Call when a thread unlocks a lock.
void tsan_release(tsan_lock_data_t* lock, tsan_lock_type_t type);

#endif
