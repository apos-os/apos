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

#ifndef APOO_SANITIZERS_TSAN_VECTOR_CLOCK_H
#define APOO_SANITIZERS_TSAN_VECTOR_CLOCK_H

#include "sanitizers/tsan/internal_types.h"
#include "sanitizers/tsan/tsan_params.h"

// A vector clock containing an epoch for each thread slot.  There can currently
// only be as many threads active at once as there are slots.
typedef struct {
  tsan_epoch_t ts[TSAN_THREAD_SLOTS];
} tsan_vc_t;

// Initialize a vector clock.
void tsan_vc_init(tsan_vc_t* vc);

// Acquire one clock into another.
void tsan_vc_acquire(tsan_vc_t* dst, const tsan_vc_t* src);

#endif
