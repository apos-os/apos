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
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/tsan_defs.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_params.h"

bool g_tsan_init = false;

// As with the heap vm_area_t, statically allocate this for the root process to
// avoid heap allocations during initialization.
static vm_area_t g_root_tsan_heap_vm_area;

void tsan_init(void) {
  KASSERT(ENABLE_TSAN);

  const memory_info_t* meminfo = get_global_meminfo();
  KASSERT(meminfo->tsan_heap.base != 0);
  KASSERT(meminfo->tsan_heap.len >=
          meminfo->heap.len * TSAN_SHADOW_MEMORY_MULT);
  // Sanity checks:
  KASSERT(meminfo->heap_size_max >= 1024 * 1024);
  KASSERT(meminfo->heap_size_max <= meminfo->heap.len);
  KASSERT(MEM_LAST_MAPPABLE_ADDR - meminfo->tsan_heap.len >=
          meminfo->tsan_heap.base);

  vm_create_kernel_mapping(&g_root_tsan_heap_vm_area, meminfo->tsan_heap.base,
                           meminfo->tsan_heap.len,
                           false /* allow_allocation */);

  // Force-allocate enough pages in the TSAN heap region to cover the entire
  // heap (actual heap size, not mapped heap size).
  KASSERT(meminfo->heap_size_max % PAGE_SIZE == 0);
  const int mapping_prot = (MEM_PROT_READ | MEM_PROT_WRITE);
  for (size_t page = 0; page < meminfo->heap_size_max / PAGE_SIZE; ++page) {
    const phys_addr_t phys_addr = page_frame_alloc();
    KASSERT(phys_addr != 0x0);
    const addr_t virt = meminfo->tsan_heap.base + page * PAGE_SIZE;
    page_frame_map_virtual(virt, phys_addr, mapping_prot,
                           MEM_ACCESS_KERNEL_ONLY, MEM_GLOBAL);

    // Zero out the page.
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      ((uint64_t*)virt)[i] = 0;
    }
  }

  // TODO(tsan): set up shadow mappings and TSAN support for non-heap memory
  // (.data and .bss sections of the kernel, in particular).

  KASSERT(meminfo->heap.base == TSAN_HEAP_START_ADDR);
  KASSERT(meminfo->tsan_heap.base == TSAN_SHADOW_START_ADDR);

  tsan_per_cpu_init();

  g_tsan_init = true;
}
