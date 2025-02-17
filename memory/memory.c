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

#include "common/kassert.h"
#include "memory/memory.h"

static memory_info_t* global_meminfo = 0;

void set_global_meminfo(memory_info_t* meminfo) {
  global_meminfo = meminfo;
}

const memory_info_t* get_global_meminfo(void) {
  return global_meminfo;
}

// Returns the next frame start address after x (or x if x is page-aligned).
addr_t next_page(addr_t x) {
  if (is_page_aligned(x)) {
    return x;
  } else {
    return  addr2page(x) + PAGE_SIZE;
  }
}

bool is_page_aligned(addr_t x) {
  return !(x & PAGE_OFFSET_MASK);
}

addr_t phys2virt(phys_addr_t x) {
  KASSERT(x >= global_meminfo->phys_maps[0].phys.base);
  KASSERT(x < global_meminfo->phys_maps[0].phys.base +
                  global_meminfo->phys_maps[0].phys.len);
  return (x - global_meminfo->phys_maps[0].phys.base) +
         global_meminfo->phys_maps[0].virt_base;
}

addr_t phys2virt_all(phys_addr_t x) {
  for (int i = 0; i < MEM_MAX_PHYS_MAPS; ++i) {
    if (global_meminfo->phys_maps[i].phys.len > 0 &&
        x >= global_meminfo->phys_maps[i].phys.base &&
        x <= global_meminfo->phys_maps[i].phys.base - 1 +
                 global_meminfo->phys_maps[i].phys.len) {
      return (x - global_meminfo->phys_maps[i].phys.base) +
             global_meminfo->phys_maps[i].virt_base;
    }
  }

  return 0;
}

phys_addr_t virt2phys(addr_t x) {
  KASSERT(x >= global_meminfo->phys_maps[0].virt_base);
  KASSERT(x - global_meminfo->phys_maps[0].phys.len <
          global_meminfo->phys_maps[0].virt_base);
  return x - global_meminfo->phys_maps[0].virt_base;
}

bool is_direct_mappable(phys_addr_t x) {
  return smmap_map_in_phys(&global_meminfo->phys_maps[0], x);
}

bool is_direct_mapped(addr_t x) {
  return smmap_map_in_virt(&global_meminfo->phys_maps[0], x);
}

bool is_valid_callback(void* cb) {
  return smmap_map_in_virt(&global_meminfo->kernel, (addr_t)cb);
}
