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
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "memory/vm_page_fault.h"
#include "proc/load/elf.h"
#include "proc/load/load.h"
#include "proc/load/load-internal.h"
#include "vfs/vfs.h"

static load_module_t g_modules[] = {
  { &elf_is_loadable, &elf_load },
  { &elf64_is_loadable, &elf64_load },
  { NULL, NULL },
};

static int read_binary(int fd, load_binary_t** binary_out) {
  *binary_out = NULL;
  for (int module_idx = 0; g_modules[module_idx].is_loadable != NULL;
       ++module_idx) {
    int result = g_modules[module_idx].is_loadable(fd);
    if (result == 0) {
      return g_modules[module_idx].load(fd, binary_out);
    }
  }
  return -ENOEXEC;
}

int load_binary(int fd, exec_info_t* exec, load_binary_t** binary_out) {
  int result = read_binary(fd, binary_out);
  if (result) {
    return result;
  }

  KASSERT(*binary_out != NULL);
  load_binary_t* binary = *binary_out;
  exec->exec_fd = -1;
  exec->load_fd = fd;
  exec->load_bin = binary;

  // TODO(aoates): verify the loaded binary (i.e. to make sure all the mappings
  // are valid, don't overlap, etc).

  // If the binary requests an interpreter, try to open and load it.
  if (binary->interp[0] != '\0') {
    KASSERT(kstrnlen(binary->interp, LOADBIN_INTERP_LEN) != LOADBIN_INTERP_LEN);
    klogfm(KL_PROC, DEBUG, "exec: binary requests interpreter '%s'\n",
           binary->interp);

    int interp_fd =
        vfs_open(binary->interp, VFS_O_RDONLY | VFS_O_INTERNAL_EXEC);
    if (interp_fd < 0) {
      klogfm(KL_PROC, INFO, "exec: unable to open interp '%s': %s\n",
             binary->interp, errorname(-interp_fd));
      return interp_fd;
    }

    load_binary_t* interp_bin = NULL;
    result = read_binary(interp_fd, &interp_bin);
    if (result) {
      klogfm(KL_PROC, INFO, "exec: unable to load interp '%s': %s\n",
             binary->interp, errorname(-result));
      vfs_close(interp_fd);
      return result;
    }

    // If we successfully loaded the interpreter, run it instead.
    KASSERT(interp_bin != NULL);
    kfree(binary);
    binary = *binary_out = exec->load_bin = interp_bin;
    // Dup the FD just in case someone is holding onto it.
    exec->exec_fd = vfs_dup(fd);
    exec->load_fd = interp_fd;
    vfs_close(fd);
  }

  // Relocate the binary if necessary.
  KASSERT(binary->base_addr % PAGE_SIZE == 0);
  for (int i = 0; i < binary->num_regions; ++i) {
    binary->regions[i].vaddr += binary->base_addr;
  }
  binary->entry += binary->base_addr;

  return 0;
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
