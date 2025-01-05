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
#include "sanitizers/tsan/tsan.h"

#include "arch/memory/page_map.h"
#include "common/kassert.h"
#include "common/math.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan_defs.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_params.h"

bool g_tsan_init = false;

// As with the heap vm_area_t, statically allocate this for the root process to
// avoid heap allocations during initialization.
static vm_area_t g_root_tsan_heap_vm_area;

static void tsan_alloc_pages(addr_t start, size_t num_pages) {
  KASSERT(start >= get_global_meminfo()->tsan_region.base);
  KASSERT(start + num_pages * PAGE_SIZE <
          get_global_meminfo()->tsan_region.base +
              get_global_meminfo()->tsan_region.len);

  klogfm(KL_GENERAL, INFO, "TSAN: allocating and zeroing %zu pages at %p\n",
         num_pages, (void*)start);
  const int mapping_prot = (MEM_PROT_READ | MEM_PROT_WRITE);
  for (size_t page = 0; page < num_pages; ++page) {
    const phys_addr_t phys_addr = page_frame_alloc();
    KASSERT(phys_addr != 0x0);
    const addr_t virt = start + page * PAGE_SIZE;
    page_frame_map_virtual(virt, phys_addr, mapping_prot,
                           MEM_ACCESS_KERNEL_ONLY, MEM_GLOBAL);

    // Zero out the page.
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      ((uint64_t*)virt)[i] = 0;
    }
  }
}

void tsan_init(void) {
  KASSERT(ENABLE_TSAN);

  const memory_info_t* meminfo = get_global_meminfo();
  KASSERT(meminfo->tsan_region.base != 0);
  KASSERT(meminfo->tsan_region.len >=
          meminfo->heap.len * TSAN_SHADOW_MEMORY_MULT);
  // Sanity checks:
  KASSERT(meminfo->heap_size_max >= 1024 * 1024);
  KASSERT(meminfo->heap_size_max <= meminfo->heap.len);
  KASSERT(MEM_LAST_MAPPABLE_ADDR - meminfo->tsan_region.len >=
          meminfo->tsan_region.base);

  vm_create_kernel_mapping(&g_root_tsan_heap_vm_area, meminfo->tsan_region.base,
                           meminfo->tsan_region.len,
                           false /* allow_allocation */);

  // Force-allocate enough pages in the TSAN heap region to cover the entire
  // heap (actual heap size, not mapped heap size).
  KASSERT(meminfo->heap_size_max % PAGE_SIZE == 0);
  const size_t heap_pages = meminfo->heap_size_max / PAGE_SIZE;
  const size_t shadow_heap_pages = TSAN_SHADOW_MEMORY_MULT * heap_pages;
  tsan_alloc_pages(TSAN_SHADOW_HEAP_START_ADDR, shadow_heap_pages);

  // Create the page metadata region.
  const size_t page_metadata_bytes = heap_pages * sizeof(tsan_page_metadata_t);
  const size_t page_metadata_pages =
      ceiling_div(page_metadata_bytes, PAGE_SIZE);
  tsan_alloc_pages(TSAN_PAGE_METADATA_START, page_metadata_pages);

  // TODO(tsan): set up shadow mappings and TSAN support for non-heap memory
  // (.data and .bss sections of the kernel, in particular).

  KASSERT(meminfo->heap.base == TSAN_HEAP_START_ADDR);
  KASSERT(meminfo->tsan_region.base == TSAN_SHADOW_HEAP_START_ADDR);

  tsan_per_cpu_init();

  g_tsan_init = true;
}
