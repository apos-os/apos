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
#include "test/kernel_tests.h"

#include "memory/arena.h"
#include "test/ktest.h"

static void basic_arena_test(void) {
  KTEST_BEGIN("Arena: basic allocation & alignment");
  arena_t a = ARENA_INIT_STATIC;
  // Test clearing an empty arena.
  KEXPECT_EQ(0, arena_num_blocks(&a));
  arena_clear(&a);

  void* x = arena_alloc(&a, 10, 1);
  kmemset(x, 'x', 10);
  x = arena_alloc(&a, 12, 1);
  kmemset(x, 'y', 12);

  // Test alignment.
  x = arena_alloc(&a, 12, 2);
  KEXPECT_EQ(0, (uintptr_t)x % 2);
  kmemset(x, '1', 12);
  KEXPECT_EQ(1, arena_num_blocks(&a));

  x = arena_alloc(&a, 12, 3);
  KEXPECT_EQ(0, (uintptr_t)x % 3);
  kmemset(x, '1', 12);

  x = arena_alloc(&a, 12, 4);
  KEXPECT_EQ(0, (uintptr_t)x % 4);
  kmemset(x, '1', 12);

  x = arena_alloc(&a, 12, 100);
  KEXPECT_EQ(0, (uintptr_t)x % 100);
  kmemset(x, '1', 12);

  x = arena_alloc(&a, 12, 128);
  KEXPECT_EQ(0, (uintptr_t)x % 128);
  kmemset(x, '1', 12);

  KEXPECT_EQ(1, arena_num_blocks(&a));
  arena_clear(&a);
  KEXPECT_EQ(0, arena_num_blocks(&a));

  // Allocating after clear should work (and allocate a block).
  x = arena_alloc(&a, 12, 128);
  KEXPECT_EQ(0, (uintptr_t)x % 128);
  kmemset(x, '1', 12);

  KEXPECT_EQ(1, arena_num_blocks(&a));
  arena_clear(&a);
  KEXPECT_EQ(0, arena_num_blocks(&a));
}

static void arena_multiblock_test(void) {
  KTEST_BEGIN("Arena: allocates multiple blocks");
  arena_t a = ARENA_INIT_STATIC;

  void* x = arena_alloc(&a, 10, 1);
  kmemset(x, 'x', 10);
  x = arena_alloc(&a, 12, 1);
  kmemset(x, 'y', 12);

  const int kChunkSize = 300;
  for (int i = 0; i < 2 * ARENA_BLOCK_SIZE / kChunkSize + 3; ++i) {
    x = arena_alloc(&a, kChunkSize, 1);
    kmemset(x, 'x', kChunkSize);
  }

  KEXPECT_EQ(3, arena_num_blocks(&a));
  arena_clear(&a);
  KEXPECT_EQ(0, arena_num_blocks(&a));


  // Test what happens if the allocation _could_ fit, except for the alignment.
  KTEST_BEGIN("Arena: alignment forces next block allocation");
  for (int i = 0; i < 7; ++i) {
    x = arena_alloc(&a, ARENA_BLOCK_SIZE / 8, 1);
    kmemset(x, 'x', ARENA_BLOCK_SIZE / 8);
  }
  KEXPECT_EQ(1, arena_num_blocks(&a));

  // We have 1/8 * ARENA_BLOCK_SIZE - epsilon bytes left.
  while (a.offset < ARENA_BLOCK_SIZE - 140) {
    x = arena_alloc(&a, 10, 1);
    kmemset(x, 'x', 10);
  }

  while (a.offset < ARENA_BLOCK_SIZE - 127) {
    x = arena_alloc(&a, 1, 1);
    kmemset(x, 'x', 1);
  }

  KEXPECT_EQ(1, arena_num_blocks(&a));
  KEXPECT_EQ(a.offset, ARENA_BLOCK_SIZE - 127);
  x = arena_alloc(&a, 127, 128);
  KEXPECT_EQ(0, (uintptr_t)x % 128);
  kmemset(x, 'x', 127);
  KEXPECT_EQ(2, arena_num_blocks(&a));
  KEXPECT_LT(a.offset, ARENA_BLOCK_SIZE / 8);

  arena_clear(&a);
}

static void arena_block_end_test(void) {
  KTEST_BEGIN("Arena: test allocating right up to block end");
  arena_t a = ARENA_INIT_STATIC;

  const int kChunkSize = 100;
  while (a.offset < ARENA_BLOCK_SIZE - kChunkSize) {
    void* x = arena_alloc(&a, kChunkSize, 1);
    kmemset(x, 'x', kChunkSize);
  }
  KEXPECT_EQ(1, arena_num_blocks(&a));

  while (a.offset < ARENA_BLOCK_SIZE) {
    void* x = arena_alloc(&a, 1, 1);
    kmemset(x, 'x', 1);
  }
  KEXPECT_EQ(1, arena_num_blocks(&a));

  void* x = arena_alloc(&a, 1, 1);
  kmemset(x, 'x', 1);
  KEXPECT_EQ(2, arena_num_blocks(&a));

  arena_clear(&a);
}

void arena_test(void) {
  KTEST_SUITE_BEGIN("Arena tests");
  basic_arena_test();
  arena_multiblock_test();
  arena_block_end_test();
}
