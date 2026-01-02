// Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#include "os/core/loader/ld_alloc.h"

#include <stdint.h>

#include "common/math.h"
#include "os/core/loader/ld_assert.h"

#define LD_HEAP_SIZE (32 * 1024)

// Static heap that's lazily allocated.
static uint8_t g_ld_heap[LD_HEAP_SIZE];
static uint8_t* g_ld_heap_ptr = g_ld_heap;
static uint8_t* g_ld_heap_end = &g_ld_heap[0] + LD_HEAP_SIZE;

void* ld_alloc(size_t len) {
  g_ld_heap_ptr =
      (uint8_t*)align_up((uintptr_t)g_ld_heap_ptr, min(len, sizeof(void*)));
  KASSERT(g_ld_heap_ptr + len < g_ld_heap_end);
  void* result = g_ld_heap_ptr;
  g_ld_heap_ptr += len;
  return result;
}
