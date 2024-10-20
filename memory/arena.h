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

// Basic arena allocator.  Arenas are thread- and interrupt-compatible, but the
// owner must use appropriate locking around them if needed.
#ifndef APOO_MEMORY_ARENA_H
#define APOO_MEMORY_ARENA_H

#include <stdint.h>

#include "common/types.h"
#include "memory/allocator.h"

#define ARENA_BLOCK_SIZE (2 << 15)  // 64k
#define ARENA_MAX_ALIGN 128

typedef struct {
  uintptr_t base;
  ssize_t offset;
} arena_t;

#define ARENA_INIT_STATIC { 0, 0 }

// If a requested allocation is too large (larger than ~ARENA_BLOCK_SIZE/2) then
// a dedicated block will be allocated for it.  If done more than occasionally,
// this defeats the purpose of an arena.  However it makes it easy to use the
// arena with hash tables (which have occasional large allocations and frequent
// small ones).
void* arena_alloc(arena_t* arena, size_t n, size_t alignment);

// Clear all allocated memory from the arena.  A cleared arena can be
// deallocated safely.
void arena_clear(arena_t* arena);

// Make an allocator for the given arena.  The arena must outlive use of the
// allocator.
void arena_make_alloc(arena_t* arena, allocator_t* alloc);

// For tests.
int arena_num_blocks(const arena_t* arena);

#endif
