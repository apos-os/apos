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

#include "archs/i586/internal/memory/page_fault-x86.h"
#include "common/debug.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "test/test_params.h"

// The maximum amount of memory (in MB) that the test_alloc_all test will
// attempt to allocate.  If it's too big, we might run out of space to track all
// the pages; if it's too small (smaller than the actual memory of the machine),
// we don't allocate them all and the test will fail.
#define MAX_MEMORY 512

static void fill_frame(phys_addr_t frame_start, uint32_t x) {
  uint32_t* frame = (uint32_t*)(phys2virt(frame_start));
  for (uint32_t i = 0; i < PAGE_SIZE / 4; ++i) {
    frame[i] = x;
  }
}

static void check_frame(phys_addr_t frame_start, uint32_t x) {
  uint32_t matched_words = 0;
  uint32_t* frame = (uint32_t*)(phys2virt(frame_start));
  for (uint32_t i = 0; i < PAGE_SIZE / 4; ++i) {
    if (frame[i] == x) {
      matched_words++;
    }
  }
  KEXPECT_EQ(matched_words, PAGE_SIZE / sizeof(uint32_t));
}

void test_alloc_all(void) {
  KTEST_BEGIN("allocate all pages test");

  // This test will only work up to 100MB of ram.
  const unsigned long MAX_PAGES = MAX_MEMORY * 1024 * 1024 / PAGE_SIZE;
  phys_addr_t* pages = kmalloc(sizeof(phys_addr_t) * MAX_PAGES);
  KASSERT(pages != 0x0);

  unsigned long i = 0;
  while (i < MAX_PAGES) {
    pages[i] = page_frame_alloc();
    if (!pages[i]) {
      break;
    }
    i++;
  }

  KEXPECT_LT(i, MAX_PAGES);
  KLOG("total allocated pages: %lu (%lu bytes)\n", i, i * PAGE_SIZE);

  // Free all those pages we just allocated, in opposite order (for the hell of
  // it).
  for (unsigned long i2 = 0; i2 < i; i2++) {
    page_frame_free_nocheck(pages[i2]);
  }
  kfree(pages);
}

void test_basic(void) {
  KTEST_BEGIN("basic test");

  phys_addr_t page1, page2, page3;
  {
    PUSH_AND_DISABLE_INTERRUPTS();
    size_t init = page_frame_allocated_pages();
    page1 = page_frame_alloc();
    page2 = page_frame_alloc();
    page3 = page_frame_alloc();
    KEXPECT_EQ(init + 3, page_frame_allocated_pages());
    POP_INTERRUPTS();
  }

  // Make sure we got physical, not virtual, page addresses.
  KEXPECT_LT(page1, 0xC0000000);
  KEXPECT_LT(page2, 0xC0000000);
  KEXPECT_LT(page3, 0xC0000000);

  // Make sure they're page-aligned.
  KEXPECT_EQ(0, page1 % PAGE_SIZE);
  KEXPECT_EQ(0, page2 % PAGE_SIZE);
  KEXPECT_EQ(0, page3 % PAGE_SIZE);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    check_frame(page1, 0xCAFEBABE);
    check_frame(page2, 0xCAFEBABE);
    check_frame(page3, 0xCAFEBABE);
  }

  fill_frame(page1, 0x11111111);
  fill_frame(page2, 0x22222222);
  fill_frame(page3, 0x33333333);

  check_frame(page1, 0x11111111);
  check_frame(page2, 0x22222222);
  check_frame(page3, 0x33333333);

  page_frame_free(page1);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    check_frame(page1, 0xDEADBEEF);
  }
  check_frame(page2, 0x22222222);
  check_frame(page3, 0x33333333);

  page_frame_free(page2);
  page_frame_free(page3);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    check_frame(page1, 0xDEADBEEF);
    check_frame(page2, 0xDEADBEEF);
    check_frame(page3, 0xDEADBEEF);
  }

  phys_addr_t page4 = page_frame_alloc();
  phys_addr_t page5 = page_frame_alloc();
  phys_addr_t page6 = page_frame_alloc();

  // Pages 4-6 should be equal to pages 1-3 in reverse order.
  KEXPECT_EQ(page1, page6);
  KEXPECT_EQ(page2, page5);
  KEXPECT_EQ(page3, page4);

  {
    PUSH_AND_DISABLE_INTERRUPTS();
    size_t init = page_frame_allocated_pages();
    page_frame_free(page4);
    page_frame_free(page5);
    page_frame_free(page6);
    KEXPECT_EQ(init - 3, page_frame_allocated_pages());
    POP_INTERRUPTS();
  }

  // TODO(aoates): allow expectations of kasserts (as with expected page faults)
  // so we can test this.
  //print("double-free: should kassert");
  //page_frame_free(page4);
}

static void* mt_page_alloc_thread(void* arg) {
  sched_enable_preemption_for_test();
  notification_t* done = (notification_t*)arg;

  uint32_t rand = (uintptr_t)&done;
  const size_t kMaxPages = 10;
  phys_addr_t pages[kMaxPages];
  size_t page = 0;
  // Have two loops so that we don't accidentally cross-thread synchronize on
  // the notification too frequently.
  int total = 0;
  while (!ntfn_has_been_notified(done)) {
    for (int i = 0; i < 1000; ++i) {
      rand = fnv_hash(rand);
      KASSERT(rand != 0);
      if (page == 0 || (rand % 2 == 0 && page < kMaxPages)) {
        pages[page] = page_frame_alloc();
        page++;
        total++;
      } else {
        KASSERT(page > 0);
        page--;
        page_frame_free(pages[page]);
      }
    }
  }

  for (size_t i = 0; i < page; ++i) {
    page_frame_free(pages[i]);
  }
  KLOG("Page alloc thread: allocated %d pages total during test\n", total);
  sched_disable_preemption();
  return NULL;
}

static void multithread_test(void) {
  KTEST_BEGIN("page allocator multi-threaded test");
  const int kNumThreads = 2 * CONCURRENCY_TEST_THREADS_MULT;
  kthread_t threads[kNumThreads];
  notification_t done;
  ntfn_init(&done);
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i], &mt_page_alloc_thread,
                                     &done));
  }

  ksleep(100 * CONCURRENCY_TEST_ITERS_MULT);
  ntfn_notify(&done);
  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
}

void page_alloc_test(void) {
  KTEST_SUITE_BEGIN("page_frame_alloc() test");

  test_alloc_all();
  test_basic();
  multithread_test();
}
