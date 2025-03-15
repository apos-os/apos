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
#include "proc/kthread-internal.h"
#include "proc/kthread.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan_defs.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_params.h"

static bool g_tsan_mem_init = false;
int g_tsan_init = 0;

// As with the heap vm_area_t, statically allocate this for the root process to
// avoid heap allocations during initialization.
static vm_area_t g_root_tsan_heap_vm_area;

static void tsan_alloc_pages(addr_t start, size_t num_pages) {
  KASSERT(start % PAGE_SIZE == 0);
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

// Set up a TSAN-mapped region.  Allocates and initializes all the shadow and
// metadata pages needed to cover the given virtual address range.
static void tsan_map_vregion(addr_t start, size_t len) {
  KASSERT(start % PAGE_SIZE == 0);
  KASSERT(start >= TSAN_MAPPED_START_ADDR);
  KASSERT(start + len - TSAN_MAPPED_LEN_ADDR < TSAN_MAPPED_START_ADDR);
  const size_t len_pages = ceiling_div(len, PAGE_SIZE);
  const size_t offset = start - TSAN_MAPPED_START_ADDR;
  KASSERT(offset % PAGE_SIZE == 0);
  klogfm(KL_GENERAL, INFO, "TSAN: mapping virtual region %p-%p\n",
         (void*)start, (void*)(start + len));

  // Allocate the shadow pages.
  const size_t shadow_offset = TSAN_SHADOW_MEMORY_MULT * offset;
  const size_t shadow_pages = TSAN_SHADOW_MEMORY_MULT * len_pages;
  tsan_alloc_pages(TSAN_SHADOW_START_ADDR + shadow_offset, shadow_pages);

  // Create the page metadata region.
  // N.B.: this may overlap with other calls to tsan_map_vregion() if the
  // regions are close to each other (within ~4MB), in which case this will
  // panic.  In that case this code will need to be updated to deal with that.

  // Illustration, showing a pmdata byte region that is less that one page but
  // crosses a page boundary, and therefore requires two full pages to be
  // allocated to it:
  // |             |             |             |  <-- page boundaries
  // |             |          AAAAAAAA         |  <-- pmdata actual bytes
  // |             |xxxxxxxxxxAAAAAAAA         |  <-- pmdata offset aligned
  // |             |xxxxxxxxxxAAAAAAAAyyyyyyyyy|  <-- full allocated region

  // First get the byte offset and length of our new metadata region.
  const size_t pmdata_offset_bytes =
      (offset / PAGE_SIZE) * sizeof(tsan_page_metadata_t);
  const size_t pmdata_len_bytes = len_pages * sizeof(tsan_page_metadata_t);

  // Now round down to get the first page address we need to map containing that
  // byte offset (adds "xxx" region above).
  const size_t pmdata_offset_aligned =
      PAGE_SIZE * (pmdata_offset_bytes / PAGE_SIZE);

  // ...and use the actual "end" address in bytes to calculate the number of
  // pages to map (adds "yyy" region above).
  const size_t pmdata_pages = ceiling_div(
      pmdata_offset_bytes + pmdata_len_bytes - pmdata_offset_aligned,
      PAGE_SIZE);
  KASSERT(pmdata_offset_aligned + pmdata_pages * PAGE_SIZE <
          TSAN_PAGE_METADATA_LEN);
  tsan_alloc_pages(TSAN_PAGE_METADATA_START + pmdata_offset_aligned,
                   pmdata_pages);
}

void tsan_init_shadow_mem(void) {
  KASSERT(ENABLE_TSAN);
  KASSERT(!g_tsan_mem_init);
  KASSERT(!g_tsan_init);

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
  tsan_map_vregion(meminfo->heap.base, meminfo->heap_size_max);

  // Allocate shadow and metadata for the static data (.data/.bss) areas.
  KASSERT(meminfo->kernel_writable_data.len > 0);
  tsan_map_vregion(meminfo->kernel_writable_data.base,
                   meminfo->kernel_writable_data.len);

  // Statically allocate the sync object table.
  KASSERT(TSAN_SYNC_OBJ_TABLE_LEN % PAGE_SIZE == 0);
  tsan_alloc_pages(TSAN_SYNC_OBJ_TABLE_START,
                   TSAN_SYNC_OBJ_TABLE_LEN / PAGE_SIZE);

  KASSERT(meminfo->tsan_region.base == TSAN_SHADOW_START_ADDR);
  g_tsan_mem_init = true;
}

void tsan_init(void) {
  KASSERT(ENABLE_TSAN);
  KASSERT(g_tsan_mem_init);
  KASSERT(!g_tsan_init);

  tsan_per_cpu_init();

  __atomic_store_n(&g_tsan_init, 1, ATOMIC_RELEASE);
}
