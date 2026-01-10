// Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#include "os/core/loader/map.h"

#include "common/math.h"
#include "os/core/loader/ld_assert.h"
#include "os/core/loader/ld_string.h"
#include "os/core/loader/syscalls.h"

#define addr2page(x) (x & ~0xfff)
#define KASSERT_DBG(x) KASSERT(x)
#define next_page(x) align_up((x), PAGE_SIZE)
#include "proc/load/load-internal.c"

static const char* prot2str(int prot, char* buf) {
  kstrcpy(buf, "   ");
  if (prot & MEM_PROT_READ) buf[0] = 'R';
  if (prot & MEM_PROT_WRITE) buf[1] = 'W';
  if (prot & MEM_PROT_EXEC) buf[2] = 'X';
  return buf;
}

int load_map_binary(int fd, const load_binary_t* binary) {
  // Create a mapping for each region.
  for (int reg = 0; reg < binary->num_regions; ++reg) {
    // Split the region into 3 separate, mappable regions.
    load_region_t map_regions[3];
    load_pagify_region(&binary->regions[reg], &map_regions[0], &map_regions[1],
                       &map_regions[2]);

    for (int i = 0; i < 3; ++i) {
      const load_region_t* mr = &map_regions[i];
      if (mr->mem_len == 0) continue;
      KASSERT(mr->vaddr % PAGE_SIZE == 0);
      KASSERT(mr->file_offset % PAGE_SIZE == 0);

      int flags = KMAP_PRIVATE | KMAP_FIXED;
      if (mr->file_len == 0) flags |= KMAP_ANONYMOUS;

      // Round up the mem_len to be an even page multiple.
      // TODO(aoates): mmap should support non-even page lengths, to match the
      // standard behavior.
      const addr_t mem_len = next_page(mr->mem_len);

      char buf[10];
      LOG(2,
          "  Mapping file [%#10lx - %#10lx] to vaddr [%#10lx - %#10lx] (%s)\n",
          mr->file_offset, mr->file_offset + mr->file_len, mr->vaddr,
          mr->vaddr + mr->mem_len, prot2str(mr->prot, buf));
      void* addr_out = (void*)mr->vaddr;
      int result = ld_mmap(&addr_out, mem_len, mr->prot, flags,
                           (flags & KMAP_ANONYMOUS) ? -1 : fd, mr->file_offset);
      KASSERT(result < 0 || addr_out == (void*)mr->vaddr);
      if (result < 0) {
        LOG(0, "Error: mapping region %d[%d] failed: %d\n", reg, i, -result);
        ld_exit(1);
      }

      // If the region is a hybrid file/memory region, zero out the memory
      // portion.
      if (mr->file_len > 0 && mr->mem_len > mr->file_len) {
        void* const to_zero = (void*)(mr->vaddr + mr->file_len);
        const unsigned int to_zero_len = mr->mem_len - mr->file_len;
        kmemset(to_zero, 0, to_zero_len);
      }
    }
  }

  return 0;
}
