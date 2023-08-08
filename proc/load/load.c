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

#include <stddef.h>

#include "common/dynamic-config.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/math.h"
#include "common/kstring.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "memory/vm_page_fault.h"
#include "proc/load/elf.h"
#include "proc/load/load.h"
#include "proc/load/load-internal.h"

static load_module_t g_modules[] = {
  { &elf_is_loadable, &elf_load },
  { &elf64_is_loadable, &elf64_load },
  { NULL, NULL },
};

int load_binary(int fd, load_binary_t** binary_out) {
  for (int module_idx = 0; g_modules[module_idx].is_loadable != NULL;
       ++module_idx) {
    int result = g_modules[module_idx].is_loadable(fd);
    if (result == 0) {
      return g_modules[module_idx].load(fd, binary_out);
    }
  }

  // TODO(aoates): verify the loaded binary (i.e. to make sure all the mappings
  // are valid, don't overlap, etc).

  return -ENOEXEC;
}

void load_pagify_region(const load_region_t* orig_region,
                        load_region_t* region0,
                        load_region_t* region1,
                        load_region_t* region2) {
  KASSERT(orig_region->file_offset % PAGE_SIZE ==
          orig_region->vaddr % PAGE_SIZE);
  const addr_t adj_vaddr = addr2page(orig_region->vaddr);
  const addr_t adj_offset = addr2page(orig_region->file_offset);
  const addr_t adj_file_length =
      (orig_region->file_offset % PAGE_SIZE) + orig_region->file_len;
  const addr_t adj_mem_length =
      (orig_region->file_offset % PAGE_SIZE) + orig_region->mem_len;
  KASSERT_DBG(adj_mem_length >= adj_file_length);

  region0->prot = region1->prot = region2->prot = orig_region->prot;

  // Split into up to 3 regions: the file region, the file/memory region, and
  // the memory-only region.
  region0->file_offset = adj_offset;
  region0->vaddr = adj_vaddr;
  region0->file_len = region0->mem_len = addr2page(adj_file_length);

  region1->file_offset = adj_offset + region0->file_len;
  region1->vaddr = adj_vaddr + region0->mem_len;
  region1->file_len = adj_file_length % PAGE_SIZE;
  region1->mem_len =
      min((addr_t)PAGE_SIZE, adj_mem_length - addr2page(adj_file_length));

  KASSERT_DBG(region0->mem_len + region1->mem_len >= adj_file_length);
  region2->file_offset = 0;  // Unused.
  region2->file_len = 0;  // Memory only.
  region2->vaddr = next_page(region1->vaddr + region1->mem_len);
  if (region0->mem_len + region1->mem_len > adj_mem_length) {
    region2->mem_len = 0;
  } else {
    region2->mem_len = adj_mem_length - region0->mem_len - region1->mem_len;
  }
}

int load_map_binary(int fd, const load_binary_t* binary) {
  // Create a mapping for each region.
  for (int reg = 0; reg < binary->num_regions; ++reg) {
    // Split the region into 3 separate, mappable regions.
    load_region_t map_regions[3];
    load_pagify_region(&binary->regions[reg], &map_regions[0], &map_regions[1],
                       &map_regions[2]);

    for (int i = 0; i < 3; ++i) {
      if (map_regions[i].mem_len == 0) continue;
      KASSERT(map_regions[i].vaddr % PAGE_SIZE == 0);
      KASSERT(map_regions[i].file_offset % PAGE_SIZE == 0);

      int flags = KMAP_PRIVATE | KMAP_FIXED;
      if (map_regions[i].file_len == 0) flags |= KMAP_ANONYMOUS;

      // Round up the mem_len to be an even page multiple.
      // TODO(aoates): mmap should support non-even page lengths, to match the
      // standard behavior.
      const addr_t mem_len = next_page(map_regions[i].mem_len);

      void* addr_out = 0x0;
      int result = do_mmap((void*)map_regions[i].vaddr, mem_len,
                           map_regions[i].prot, flags,
                           (flags & KMAP_ANONYMOUS) ? -1 : fd,
                           map_regions[i].file_offset, &addr_out);
      KASSERT(result < 0 || addr_out == (void*)map_regions[i].vaddr);
      if (result < 0) {
        klogfm(KL_PROC, ERROR, "mapping region %d[%d] failed: %s\n", reg, i,
               errorname(-result));
        // TODO(aoates): tear down mappings.
        return result;
      }

      // If the region is a hybrid file/memory region, zero out the memory
      // portion.
      if (map_regions[i].file_len > 0 &&
          map_regions[i].mem_len > map_regions[i].file_len) {
        void* const to_zero =
            (void*)(map_regions[i].vaddr + map_regions[i].file_len);
        const unsigned int to_zero_len =
            map_regions[i].mem_len - map_regions[i].file_len;
        kmemset(to_zero, 0, to_zero_len);
      }

      if (ENABLE_PRELOAD_USER_BINS) {
        for (size_t page  = 0; page < mem_len / PAGE_SIZE; ++page) {
          addr_t addr = map_regions[i].vaddr + page * PAGE_SIZE;
          vm_handle_page_fault(addr, VM_FAULT_NOT_PRESENT, VM_FAULT_READ,
                               VM_FAULT_USER);
        }
      }
    }
  }

  return 0;
}
