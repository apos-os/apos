// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <stdint.h>

#include "kmalloc.h"
#include "kmalloc-internal.h"
#include "test/ktest.h"

static void macros_test() {
  KTEST_BEGIN("kmalloc macros");

  uint8_t block_mem[120];
  block_t* block = (block_t*)&block_mem;
  block->length = 100;

  KEXPECT_EQ((uint32_t)block, BLOCK_START(block));
  KEXPECT_EQ((uint32_t)block + sizeof(block_t) + 100, BLOCK_END(block));
  KEXPECT_EQ(sizeof(block_t) + 100, BLOCK_SIZE(block));
}

void kmalloc_test() {
  KTEST_SUITE_BEGIN("kmalloc");

  macros_test();
}
