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

#ifndef APOO_SANITIZERS_TSAN_SHADOW_CELL_H
#define APOO_SANITIZERS_TSAN_SHADOW_CELL_H

#include <stdint.h>

#include "common/attributes.h"
#include "sanitizers/tsan/tsan_params.h"

// Contents of a single shadow cell, representing a recent access to the
// associated memory address from a thread.
// TODO(aoates): consider trying to squeeze this down to 32 bits --- if we
// restrict to 64 thread slots, then we'd still be able to fit 20 bits of epoch
// in, which is probably plenty.
typedef struct {
  uint32_t epoch;
  uint8_t sid;
  uint8_t mask;  // Which bytes were accessed (gets offset and size).
  uint8_t is_write:1;
  uint8_t is_atomic:1;
  uint16_t _unused2:14;
} tsan_shadow_t;

_Static_assert(sizeof(tsan_shadow_t) == TSAN_SHADOW_CELL_SIZE,
               "Bad tsan_shadow_t");

typedef union {
  tsan_shadow_t s;
  uint64_t raw;
} tsan_shadow_punner_t;

static ALWAYS_INLINE uint64_t shadow2raw(tsan_shadow_t s) {
  return ((tsan_shadow_punner_t)s).raw;
}

// Metadata about an entire page of memory.
typedef struct {
  uint32_t is_stack : 1;
} tsan_page_metadata_t;

_Static_assert(sizeof(tsan_page_metadata_t) == sizeof(uint32_t),
               "Bad tsan_page_metadata_t");

#endif
