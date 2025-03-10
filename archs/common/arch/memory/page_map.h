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

// Code for the low-level kernel page tables.  Handles creating/deleting page
// mappings.
//
// Global mappings
// ===============
// Global regions are memory regions whose mappings are shared between all
// processes.  This is done by sharing the mid- and low- level page structures
// between all processes.
//
// A global region has a minimum size, depending on the architecture (4MB for
// x86).  Global regions are established by calling
// page_frame_init_global_mapping() at boot time, in the address space of the
// initial process.  Then, when each new process is created,
// page_frame_link_global_mapping() is called to create the mapping in the new
// process's address space.

#ifndef APOO_ARCHS_COMMON_ARCH_MEMORY_PAGE_MAP_H
#define APOO_ARCHS_COMMON_ARCH_MEMORY_PAGE_MAP_H

#include <stdint.h>

#include "common/types.h"
#include "memory/flags.h"
#include "memory/memory.h"

// Establishes a mapping from the given virtual address to the physical address
// in the currently-loaded page tables.
//
// prot should be an OR combination of MEM_PROT_* values.  access should be one
// of the MEM_ACCESS_* values.  flags should be a combination of the other mem
// flags.
//
// REQUIRES: virt and phys are page-aligned.
void page_frame_map_virtual(addr_t virt, phys_addr_t phys, int prot,
                            mem_access_t access, int flags);

// As above, but change the protection, access, and flags of an existing mapping
// (not changing the actual physical address mapping).
void page_frame_remap_virtual(addr_t virt, int prot, mem_access_t access,
                              int flags);

// Removes the mapping for the given virtual address from the currently-loaded
// page table (by marking it non-present), if it exists.
//
// REQUIRES: virt is page-aligned.
void page_frame_unmap_virtual(addr_t virt);

// Removes mappings for an entire range of addresses.
//
// REQUIRES: virt and length are page-aligned.
void page_frame_unmap_virtual_range(addr_t virt, addrdiff_t length);

// Allocate and initialize a new page directory (e.g. for a new process), and
// return it's (physical) address.
page_dir_ptr_t page_frame_alloc_directory(void);

// Free the given page directory.
void page_frame_free_directory(page_dir_ptr_t page_directory);

// Initializes a region of memory as a globally-shared region.  This must be
// called once per region in the initial address space, before any new processes
// are created.
//
// Any new mappings created in the region (in any process) will be seen by all
// other processes, assuming that page_frame_link_global_mapping() is called
// appropriately.
//
// REQUIRES: addr and length are aligned and sized according to the minimum
// global region size for the current architecture.
void page_frame_init_global_mapping(addr_t addr, addr_t length);

// Link a global region (which must be present in the current address space) to
// a new address space, represented by the given page directory pointer.
//
// REQUIRES: addr and length match a previous call to
// page_frame_init_global_mapping() in the current address space.
void page_frame_link_global_mapping(page_dir_ptr_t target,
                                    addr_t addr, addr_t length);

#endif
