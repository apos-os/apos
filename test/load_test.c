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

#include "common/errno.h"
#include "common/kassert.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "proc/load/load.h"
#include "proc/load/load-internal.h"
#include "test/ktest.h"

// Pagify a region with the given attributes, and verify the output is OK.
void test_pagify(addr_t file_offset,
                 addr_t vaddr,
                 addr_t file_len,
                 addr_t mem_len) {
  load_region_t region;
  region.file_offset = file_offset;
  region.vaddr = vaddr;
  region.file_len = file_len;
  region.mem_len = mem_len;
  region.prot = MEM_PROT_READ | MEM_PROT_EXEC;

  load_region_t page_regions[3];
  load_pagify_region(&region, &page_regions[0], &page_regions[1],
                     &page_regions[2]);

  // Verify all the regions have the correct flags and are page aligned.
  for (int i = 0; i < 3; ++i) {
    KEXPECT_EQ(0, page_regions[i].file_offset % PAGE_SIZE);
    KEXPECT_EQ(0, page_regions[i].vaddr % PAGE_SIZE);
    KEXPECT_GE(page_regions[i].mem_len, page_regions[i].file_len);
    // All but the last region should be even-page-sized.
    if (i == 0 || (i == 1 && page_regions[2].mem_len != 0)) {
      KEXPECT_EQ(0, page_regions[i].mem_len % PAGE_SIZE);
    }
    KEXPECT_EQ(MEM_PROT_READ | MEM_PROT_EXEC, page_regions[i].prot);
  }

  // The first region should be file-only and the third memory-only.
  KEXPECT_EQ(page_regions[0].file_len, page_regions[0].mem_len);
  KEXPECT_EQ(0, page_regions[2].file_len);

  // The middle region should be at most 1 page.
  KEXPECT_LE(page_regions[1].mem_len, PAGE_SIZE);

  // The whole region should have grown by exactly the amount needed to
  // page-align it.
  KEXPECT_EQ((file_offset % PAGE_SIZE) + mem_len,
             page_regions[0].mem_len +
             page_regions[1].mem_len +
             page_regions[2].mem_len);
  KEXPECT_EQ((file_offset % PAGE_SIZE) + file_len,
             page_regions[0].file_len +
             page_regions[1].file_len +
             page_regions[2].file_len);

  // Make sure the offsets are valid (they match the input, and the three output
  // regions are aligned).
  KEXPECT_EQ(PAGE_SIZE * (file_offset / PAGE_SIZE),
             page_regions[0].file_offset);
  KEXPECT_EQ(PAGE_SIZE * (vaddr / PAGE_SIZE),
             page_regions[0].vaddr);
  for (int i = 1; i < 3; ++i) {
    if (page_regions[i].file_len > 0) {
      KEXPECT_EQ(page_regions[i - 1].file_offset + page_regions[i - 1].mem_len,
                 page_regions[i].file_offset);
    }
    if (page_regions[i].mem_len > 0) {
      KEXPECT_EQ(page_regions[i - 1].vaddr + page_regions[i - 1].mem_len,
                 page_regions[i].vaddr);
    }
  }
}

void proc_load_test() {
  KTEST_SUITE_BEGIN("proc load test");

  KTEST_BEGIN("load_pagify_region(): empty region");
  test_pagify(123, PAGE_SIZE + 123, 0, 0);

  KTEST_BEGIN("load_pagify_region(): page-aligned, file only");
  test_pagify(0, 0, PAGE_SIZE, PAGE_SIZE);

  KTEST_BEGIN("load_pagify_region(): offset, page-aligned, file only");
  test_pagify(PAGE_SIZE, 2 * PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);

  KTEST_BEGIN("load_pagify_region(): offset, page-aligned, memory only");
  test_pagify(PAGE_SIZE, 2 * PAGE_SIZE, 0, 3 * PAGE_SIZE);

  KTEST_BEGIN("load_pagify_region(): hybrid but page-aligned");
  test_pagify(0, 0, PAGE_SIZE, 3 * PAGE_SIZE);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, < 1 page");
  test_pagify(0, 0, 123, 456);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, == 1 page");
  test_pagify(0, 0, PAGE_SIZE - 789, PAGE_SIZE);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, > 1 page (A)");
  test_pagify(0, 0, 789, PAGE_SIZE + 123);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, > 1 page (B)");
  test_pagify(0, 0, PAGE_SIZE + 789, 2 * PAGE_SIZE + 123);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, > 1 page (B)");
  test_pagify(0, 0, 789, 2 * PAGE_SIZE + 123);

  KTEST_BEGIN("load_pagify_region(): hybrid, not page-aligned, > 1 page (C)");
  test_pagify(0, 0, PAGE_SIZE + 789, 3 * PAGE_SIZE + 123);

  KTEST_BEGIN("load_pagify_region(): complicated (A)");
  test_pagify(PAGE_SIZE + 123, 5 * PAGE_SIZE + 123, 52187, 99823);

  KTEST_BEGIN("load_pagify_region(): complicated (B)");
  test_pagify(PAGE_SIZE + 123, 5 * PAGE_SIZE + 123, 27, 99823);

  KTEST_BEGIN("load_pagify_region(): complicated (C)");
  test_pagify(2 * PAGE_SIZE - 3, 5 * PAGE_SIZE - 3, 27, 55);

  KTEST_BEGIN("load_pagify_region(): complicated (D)");
  test_pagify(2 * PAGE_SIZE - 3, 5 * PAGE_SIZE - 3,
              PAGE_SIZE + 10, PAGE_SIZE + 20);

  KTEST_BEGIN("load_pagify_region(): complicated (D)");
  test_pagify(2 * PAGE_SIZE - 3, 5 * PAGE_SIZE - 3,
              PAGE_SIZE + 10, 3 * PAGE_SIZE + 20);
}
