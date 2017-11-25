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
#include "common/types.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "memory/kmalloc-internal.h"
#include "memory/memory.h"
#include "test/ktest.h"

#define HEAP_SIZE 0x10000000

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
static size_t list_bytesize(block_t* lst) {
  size_t len = 0;
  while (lst) {
    len += sizeof(block_t);
    len += lst->length;
    lst = lst->next;
  }
  return len;
}

// Return the DATA (no headers) size of all used space on the list.
static size_t list_used_size(block_t* lst) {
  size_t len = 0;
  while (lst) {
    if (!lst->free) {
      len += lst->length;
    }
    lst = lst->next;
  }
  return len;
}

static void macros_test(void) {
  KTEST_BEGIN("kmalloc macros");

  uint8_t block_mem[120];
  block_t* block = (block_t*)&block_mem;
  block->length = 100;

  KEXPECT_EQ((addr_t)block, BLOCK_START(block));
  KEXPECT_EQ((addr_t)block + sizeof(block_t) + 100, BLOCK_END(block));
  KEXPECT_EQ(sizeof(block_t) + 100, BLOCK_SIZE(block));
}

static void init_test(void) {
  KTEST_BEGIN("kmalloc init");

  kmalloc_init();
  block_t* list = kmalloc_internal_get_block_list();
  KEXPECT_NE(NULL, list);
  KEXPECT_EQ(NULL, list->prev);
  KEXPECT_EQ(NULL, list->next);
  KEXPECT_EQ(HEAP_SIZE - sizeof(block_t), list->length);
  KEXPECT_EQ(1, list->free);
}

static void basic_test(void) {
  KTEST_BEGIN("kmalloc malloc");

  kmalloc_init();
  void* x = kmalloc(100);
  block_t* x_block = (block_t*)((addr_t)x - sizeof(block_t));
  KEXPECT_EQ(0, x_block->free);
  KEXPECT_EQ(100, x_block->length);

  // Make sure it's on the list.
  block_t* list_root = kmalloc_internal_get_block_list();
  verify_list(list_root);
  KEXPECT_EQ(2, list_length(list_root));
  KEXPECT_EQ((addr_t)x_block, (addr_t)list_root);
  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(100, list_used_size(list_root));

  // Allocate some more blocks.
  void* x2 = kmalloc(128);
  void* x3 = kmalloc(145);
  void* x4 = kmalloc(160);

  // We should still have only allocated one page.
  verify_list(list_root);
  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(100 + 128 + 145 + 160, list_used_size(list_root));

  // Allocate a big chunk.
  void* x5 = kmalloc(0xf00);
  verify_list(list_root);

  // We should have needed another page for that.
  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(0xf00 + 100 + 128 + 145 + 160, list_used_size(list_root));
  KEXPECT_EQ(6, list_length(list_root));

  // Free a block in the middle.
  kfree(x3);
  verify_list(list_root);

  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(0xf00 + 100 + 128 + 160, list_used_size(list_root));
  KEXPECT_EQ(6, list_length(list_root));

  // Free the rest.
  kfree(x);
  kfree(x2);
  kfree(x4);
  kfree(x5);

  KTEST_BEGIN("kmalloc malloc OOM");
  KEXPECT_EQ((void*)0x0, kmalloc(HEAP_SIZE + 10));

  verify_list(list_root);

  // Make sure it's all merged together.
  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(0, list_used_size(list_root));
  KEXPECT_EQ(1, list_length(list_root));

  kmalloc_log_state();
}

static void large_alloc_test(void) {
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

  KEXPECT_NE(NULL, x1);
  KEXPECT_NE(NULL, x2);
  KEXPECT_NE(NULL, x3);
  KEXPECT_NE(NULL, x4);

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

static void tiny_alloc_test(void) {
  KTEST_BEGIN("kmalloc tiny alloc");

  void* x[100];
  for (int i = 0; i < 100; ++i) {
    x[i] = kmalloc(i % 3 + 1);
    KEXPECT_NE(NULL, x[i]);
  }
  kmalloc_log_state();
  verify_list(kmalloc_internal_get_block_list());

  for (int i = 0; i < 100; ++i) {
    if (x[i]) {
      kfree(x[i]);
    }
  }
  verify_list(kmalloc_internal_get_block_list());

  KEXPECT_EQ(0, list_used_size(kmalloc_internal_get_block_list()));
  kmalloc_log_state();
}

static uint16_t rand(void) {
  static uint16_t p = 0xbeef;
  static uint16_t n = 0xabcd;
  p = n;
  uint32_t x = n * n;
  n = (x >> 8) & 0x0000ffff;
  return p ^ n;
}

static void stress_test(void) {
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
      KLOG("i = %i, ptr_idx = %i\n", i, ptr_idx);
    }
    verify_list(kmalloc_internal_get_block_list());
  }

  KLOG("freeing everything that's left...\n");
  while (ptr_idx > 0) {
    kfree(ptrs[--ptr_idx]);
  }

  KLOG("\npost-thrash\n");
  KLOG("total allocs: %i\npeak allocs: %i\n", total_allocs, max_alloced);
  KLOG("---------------\n");
  kmalloc_log_state();
  KLOG("---------------\n");

  block_t* list_root = kmalloc_internal_get_block_list();
  KEXPECT_EQ(1, list_length(list_root));
  KEXPECT_EQ(HEAP_SIZE, list_bytesize(list_root));
  KEXPECT_EQ(0, list_used_size(list_root));
}

// Make sure kmalloc/kfree are interrupt-safe.  Essentially the same as
// tiny_alloc_test() but with a timer interrupting and doing allocations as
// well.
void interrupt_test_timer_cb(void* arg) {
  void* x1 = kmalloc(1);
  void* x2 = kmalloc(1);
  void* x3 = kmalloc(1);
  void* x4 = kmalloc(1);
  kfree(x3);
  kfree(x2);
  kfree(x4);
  kfree(x1);
}
static void interrupt_test(void) {
  KTEST_BEGIN("kmalloc interrupt safety test");

  register_timer_callback(1, 1000, &interrupt_test_timer_cb, 0x0);

  for (int round = 0; round < 200; round++) {
    void* x[100];
    for (int i = 0; i < 100; ++i) {
      x[i] = kmalloc(i % 3 + 1);
      if (!x[i]) {
        KEXPECT_NE(NULL, x[i]);
      }
    }
    verify_list(kmalloc_internal_get_block_list());

    for (int i = 0; i < 100; ++i) {
      if (x[i]) {
        kfree(x[i]);
      }
    }
    verify_list(kmalloc_internal_get_block_list());

    KEXPECT_EQ(0, list_used_size(kmalloc_internal_get_block_list()));
  }
  kmalloc_log_state();
}

// Similar to interrupt_test, but doesn't do as much checking, just bangs on it.
void large_interrupt_test_timer_cb(void* arg) {
  void* x1 = kmalloc(1);
  void* x2 = kmalloc(1);
  void* x3 = kmalloc(1);
  void* x4 = kmalloc(1);
  kfree(x3);
  kfree(x2);
  kfree(x4);
  kfree(x1);
}
static void large_interrupt_test(void) {
  KTEST_BEGIN("kmalloc large interrupt safety test");

  const int kTestLengthMs = 10000;
  const apos_ms_t start_time = get_time_ms();

  register_timer_callback(10, kTestLengthMs / 10,
                          &large_interrupt_test_timer_cb, 0x0);
  int round = 0;
  while (get_time_ms() < start_time + kTestLengthMs) {
    round++;
    if (round % 100 == 0) {
      KLOG("round %d, elapsed: %d\n", round, get_time_ms() - start_time);
    }
    void* x[100];
    for (int i = 0; i < 100; ++i) {
      x[i] = kmalloc(i % 3 + 1);
    }

    for (int i = 0; i < 100; ++i) {
      if (x[i]) {
        kfree(x[i]);
      }
    }
  }
  KLOG("Did %d rounds over %d ms\n", round, kTestLengthMs);
  kmalloc_log_state();
}

static void kmalloc_aligned_test(void) {
  kmalloc_init();
  kmalloc_log_state();
  // Try allocations with a variety of alignments.
  const uint32_t kAlignments[] = {1, 2, 3, 5, 17, 32, 1234, 4096};

  for (unsigned int i = 0; i < sizeof(kAlignments) / sizeof(uint32_t); ++i) {
    const int kNumAllocs = 5;
    void* allocs[kNumAllocs];

    for (int alloc = 0; alloc < kNumAllocs; ++alloc) {
      allocs[alloc] = kmalloc_aligned(100, kAlignments[i]);
      KEXPECT_NE((void*)0x0, allocs[alloc]);
      KEXPECT_EQ(0, (addr_t)allocs[alloc] % kAlignments[i]);
    }

    for (int alloc = 0; alloc < kNumAllocs; ++alloc) {
      if (allocs[alloc]) kfree(allocs[alloc]);
    }
  }

  // TODO test: blocks that are shorter than the next aligned address
  kmalloc_log_state();
}

void kmalloc_test(void) {
  KTEST_SUITE_BEGIN("kmalloc");

  kmalloc_enable_test_mode();
  cancel_all_event_timers_for_tests();

  // NOTE: we disable klog-to-VTERM since we'll be overwriting the kmalloc
  // state, which causes problems with the vterm.  If there's anything else
  // running simultaneously with these tests that touches kmalloc'd memory, the
  // whole system will likely explode.
  klog_set_mode(KLOG_RAW_VIDEO);

  macros_test();
  init_test();
  basic_test();
  large_alloc_test();
  tiny_alloc_test();
  stress_test();
  interrupt_test();
  large_interrupt_test();
  kmalloc_aligned_test();

  // The kernel is no longer in a usable state.
  // TODO(aoates): if this ever becomes annoying, we could force-reboot the
  // kernel (by resetting the stack pointer and calling kmain).
  ktest_finish_all();
  KLOG("NOTE: kmalloc_test() ruins the kernel, so a reboot is needed.\n");
  while (1) {}
}
