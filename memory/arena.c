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
#include "memory/arena.h"

#include "common/kassert.h"
#include "common/math.h"
#include "memory/kmalloc.h"

typedef struct {
  uintptr_t next;
} arena_header_t;

static void extend_arena(arena_t* arena) {
  void* new_block = kmalloc_aligned(ARENA_BLOCK_SIZE, sizeof(arena_header_t));
  KASSERT(new_block != NULL);
  arena_header_t* hdr = (arena_header_t*)new_block;
  hdr->next = arena->base;
  arena->base = (uintptr_t)new_block;
  arena->offset = sizeof(arena_header_t);
}

void* arena_alloc(arena_t* arena, size_t n, size_t alignment) {
  KASSERT(n > 0 && n < ARENA_BLOCK_SIZE / 4);
  KASSERT(alignment > 0 && alignment <= ARENA_MAX_ALIGN);

  if (arena->base == 0) {
    extend_arena(arena);
  }

  uintptr_t result = align_up(arena->base + arena->offset, alignment);
  if (result + n > arena->base + ARENA_BLOCK_SIZE) {
    extend_arena(arena);
    result = align_up(arena->base + arena->offset, alignment);
  }

  arena->offset = result + n - arena->base;
  return (void*)result;
}

void arena_clear(arena_t* arena) {
  uintptr_t block = arena->base;
  while (block) {
    arena_header_t* hdr = (arena_header_t*)block;
    uintptr_t next = hdr->next;
    kfree((void*)block);
    block = next;
  }
  arena->base = 0;
}

int arena_num_blocks(const arena_t* arena) {
  int result = 0;
  uintptr_t block = arena->base;
  while (block) {
    result++;
    arena_header_t* hdr = (arena_header_t*)block;
    block = hdr->next;
  }
  return result;
}
