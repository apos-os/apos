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

#define MAX_ARENA_ALLOC ((ARENA_BLOCK_SIZE - sizeof(arena_header_t)) / 2)

static void extend_arena(arena_t* arena) {
  void* new_block = kmalloc_aligned(ARENA_BLOCK_SIZE, sizeof(arena_header_t));
  KASSERT(new_block != NULL);
  arena_header_t* hdr = (arena_header_t*)new_block;
  hdr->next = arena->base;
  arena->base = (uintptr_t)new_block;
  arena->offset = sizeof(arena_header_t);
}

static void* mega_alloc(arena_t* arena, size_t n, size_t alignment) {
  klogfm(KL_MEMORY, WARNING, "arena allocating mega block of %zu bytes\n", n);
  const size_t block_size =
      n + sizeof(arena_header_t) + 2 * ARENA_MAX_ALIGN;
  void* new_block = kmalloc_aligned(block_size, sizeof(arena_header_t));
  KASSERT(new_block != NULL);
  arena_header_t* hdr = (arena_header_t*)new_block;
  arena_header_t* curr_hdr = (arena_header_t*)arena->base;
  hdr->next = curr_hdr->next;
  curr_hdr->next = (uintptr_t)new_block;

  void* result = (void*)align_up((uintptr_t)new_block + sizeof(arena_header_t),
                                 alignment);
  KASSERT_DBG((uintptr_t)result + n <= (uintptr_t)new_block + block_size);
  return result;
}

void* arena_alloc(arena_t* arena, size_t n, size_t alignment) {
  KASSERT(n > 0);
  KASSERT(alignment > 0 && alignment <= ARENA_MAX_ALIGN);

  if (arena->base == 0) {
    extend_arena(arena);
  }

  if (n > MAX_ARENA_ALLOC) {
    return mega_alloc(arena, n, alignment);
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

static void* arena_alloc_alloc(void* arg, size_t n, size_t alignment) {
  return arena_alloc((arena_t*)arg, n, alignment);
}

static void arena_alloc_free(void* arg, void* ptr) {}

void arena_make_alloc(arena_t* arena, allocator_t* alloc) {
  alloc->alloc = &arena_alloc_alloc;
  alloc->free = &arena_alloc_free;
  alloc->arg = arena;
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
