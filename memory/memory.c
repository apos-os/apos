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

const memory_info_t* get_global_meminfo() {
  return global_meminfo;
}

uint32_t addr2page(uint32_t addr) {
  return addr & PAGE_INDEX_MASK;
}

// Returns the next frame start address after x (or x if x is page-aligned).
uint32_t next_page(uint32_t x) {
  if (is_page_aligned(x)) {
    return x;
  } else {
    return  addr2page(x) + PAGE_SIZE;
  }
}

int is_page_aligned(uint32_t x) {
  return !(x & PAGE_OFFSET_MASK);
}

uint32_t phys2virt(uint32_t x) {
  KASSERT(x < global_meminfo->phys_map_length);
  return x + global_meminfo->phys_map_start;
}

uint32_t virt2phys(uint32_t x) {
  KASSERT(x >= global_meminfo->phys_map_start);
  KASSERT(x - global_meminfo->phys_map_length < global_meminfo->phys_map_start);
  return x - global_meminfo->phys_map_start;
}

int is_direct_mappable(uint32_t x) {
  return (x < global_meminfo->phys_map_length);
}

int is_direct_mapped(uint32_t x) {
  return (x >= global_meminfo->phys_map_start &&
          x < global_meminfo->phys_map_start + global_meminfo->phys_map_length);
}

uint32_t phys2kernel(uint32_t x) {
  return x + global_meminfo->mapped_start;
}
