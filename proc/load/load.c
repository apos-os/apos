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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/math.h"
#include "memory/memory.h"
#include "proc/load/elf.h"
#include "proc/load/load.h"
#include "proc/load/load-internal.h"

static load_module_t g_modules[] = {
  { &elf_is_loadable, &elf_load },
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

  return -ENOTSUP;
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
