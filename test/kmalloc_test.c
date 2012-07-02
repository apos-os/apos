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

#include "common/kassert.h"
#include "kmalloc.h"
#include "kmalloc-internal.h"
#include "memory.h"
#include "test/ktest.h"

static void verify_list(block_t* lst) {
  while (lst) {
    // Dereference the pointer to make sure it's valid.
    uint8_t x = *((uint8_t*)lst);
    x = x;  // appease the compiler

    if (lst->prev) {
      KASSERT(lst->prev->next == lst);
    }
    if (lst->next) {
      KASSERT(lst->next->prev == lst);
    }

    lst = lst->next;
  }
}

static int list_length(block_t* lst) {
  int len = 0;
  while (lst) {
    len++;
    lst = lst->next;
  }
  return len;
}

// Returns the size (in bytes) of the list (including data and headers of each
// element).
static int list_size(block_t* lst) {
  int len = 0;
  while (lst) {
    len += sizeof(block_t);
    len += lst->length;
    lst = lst->next;
  }
  return len;
}

// Return the DATA (no headers) size of all used space on the list.
static int list_used_size(block_t* lst) {
  int len = 0;
  while (lst) {
    if (!lst->free) {
      len += lst->length;
    }
    lst = lst->next;
  }
  return len;
}

static void macros_test() {
  KTEST_BEGIN("kmalloc macros");

  uint8_t block_mem[120];
  block_t* block = (block_t*)&block_mem;
  block->length = 100;

  KEXPECT_EQ((uint32_t)block, BLOCK_START(block));
  KEXPECT_EQ((uint32_t)block + sizeof(block_t) + 100, BLOCK_END(block));
  KEXPECT_EQ(sizeof(block_t) + 100, BLOCK_SIZE(block));
}

static void init_test() {
  KTEST_BEGIN("kmalloc init");

  kmalloc_init();
  block_t* list = kmalloc_internal_get_block_list();
  KEXPECT_NE(0, (uint32_t)list);
  KEXPECT_EQ(0, (uint32_t)list->prev);
  KEXPECT_EQ(0, (uint32_t)list->next);
  KEXPECT_EQ(0, list->length);
  KEXPECT_EQ(0, list->free);
}

static void basic_test() {
  KTEST_BEGIN("kmalloc malloc");

  kmalloc_init();
  void* x = kmalloc(100);
  block_t* x_block = (block_t*)((uint32_t)x - sizeof(block_t));
  KEXPECT_EQ(0, x_block->free);
  KEXPECT_EQ(100, x_block->length);

  // Make sure it's on the list.
  block_t* list_root = kmalloc_internal_get_block_list();
  verify_list(list_root);
  KEXPECT_EQ(3, list_length(list_root));
  KEXPECT_EQ((uint32_t)x_block, (uint32_t)list_root->next);
  KEXPECT_EQ(PAGE_SIZE + sizeof(block_t), list_size(list_root));
  KEXPECT_EQ(100, list_used_size(list_root));

  // Allocate some more blocks.
  void* x2 = kmalloc(128);
  void* x3 = kmalloc(145);
  void* x4 = kmalloc(160);

  // We should still have only allocated one page.
  verify_list(list_root);
  KEXPECT_EQ(PAGE_SIZE + sizeof(block_t), list_size(list_root));
  KEXPECT_EQ(100 + 128 + 145 + 160, list_used_size(list_root));

  // Allocate a big chunk.
  void* x5 = kmalloc(0xf00);
  verify_list(list_root);

  // We should have needed another page for that.
  KEXPECT_EQ(2 * PAGE_SIZE + sizeof(block_t), list_size(list_root));
  KEXPECT_EQ(0xf00 + 100 + 128 + 145 + 160, list_used_size(list_root));
  KEXPECT_EQ(8, list_length(list_root));

  // Free a block in the middle.
  kfree(x3);
  verify_list(list_root);

  KEXPECT_EQ(2 * PAGE_SIZE + sizeof(block_t), list_size(list_root));
  KEXPECT_EQ(0xf00 + 100 + 128 + 160, list_used_size(list_root));
  KEXPECT_EQ(8, list_length(list_root));

  // Free the rest.
  kfree(x);
  kfree(x2);
  kfree(x4);
  kfree(x5);
  verify_list(list_root);

  // Make sure it's all merged together.
  KEXPECT_EQ(2 * PAGE_SIZE + sizeof(block_t), list_size(list_root));
  KEXPECT_EQ(0, list_used_size(list_root));
  KEXPECT_EQ(2, list_length(list_root));

  kmalloc_log_state();
}

static void large_alloc_test() {
  KTEST_BEGIN("kmalloc large alloc");

  void* x1 = kmalloc(PAGE_SIZE / 2);
  kmalloc_log_state();
  void* x2 = kmalloc(PAGE_SIZE);
  kmalloc_log_state();
  void* x3 = kmalloc(PAGE_SIZE * 2);
  kmalloc_log_state();
  void* x4 = kmalloc(PAGE_SIZE * 4);
  kmalloc_log_state();
  verify_list(kmalloc_internal_get_block_list());

  KEXPECT_NE(0x0, (uint32_t)x1);
  KEXPECT_NE(0x0, (uint32_t)x2);
  KEXPECT_NE(0x0, (uint32_t)x3);
  KEXPECT_NE(0x0, (uint32_t)x4);

  if (x1 && x2 && x3 && x4) {
    kfree(x1);
    kfree(x2);
    kfree(x3);
    kfree(x4);
  }
  verify_list(kmalloc_internal_get_block_list());

  KEXPECT_EQ(0, list_used_size(kmalloc_internal_get_block_list()));
  kmalloc_log_state();
}

static uint16_t rand() {
  static uint16_t p = 0xbeef;
  static uint16_t n = 0xabcd;
  p = n;
  uint32_t x = n * n;
  n = (x >> 8) & 0x0000ffff;
  return p ^ n;
}

static void stress_test() {
  KTEST_BEGIN("stress test");
  kmalloc_init();

  void* ptrs[500];
  int ptr_idx = 0;
  int total_allocs = 0;
  int max_alloced = 0;

  for (int i = 0; i < 500; ++i) {
    int threshold = 2;
    if (ptr_idx < 200) {
      threshold = 3;
    } else if (ptr_idx > 400) {
      threshold = 1;
    }
    if ((ptr_idx == 0 || rand() % 4 < threshold) && ptr_idx < 500) {
      ptrs[ptr_idx++] = kmalloc(rand() % 3900);
      total_allocs++;
    } else {
      KASSERT(ptr_idx > 0);
      kfree(ptrs[--ptr_idx]);
    }

    if (ptr_idx > max_alloced) {
      max_alloced = ptr_idx;
    }

    if (i % 20 == 0) {
      klogf("i = %i, ptr_idx = %i\n", i, ptr_idx);
    }
    verify_list(kmalloc_internal_get_block_list());
  }

  klogf("freeing everything that's left...\n");
  while (ptr_idx > 0) {
    kfree(ptrs[--ptr_idx]);
  }

  klogf("\npost-thrash\n");
  klogf("total allocs: %i\npeak allocs: %i\n", total_allocs, max_alloced);
  klog("---------------\n");
  kmalloc_log_state();
  klog("---------------\n");

  block_t* list_root = kmalloc_internal_get_block_list();
  KEXPECT_EQ(2, list_length(list_root));
  KEXPECT_EQ(0, (list_size(list_root) - sizeof(block_t))% PAGE_SIZE);  // even # of pages
  KEXPECT_EQ(0, list_used_size(list_root));
}

void kmalloc_test() {
  KTEST_SUITE_BEGIN("kmalloc");

  macros_test();
  init_test();
  basic_test();
  large_alloc_test();
  stress_test();
}
