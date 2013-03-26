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

// Code for the low-level kernel page frame allocator and page tables.  Handles
// allocating physical pages, and creating/deleting page mappings.

#ifndef APOO_MEMORY_PAGE_ALLOC_H
#define APOO_MEMORY_PAGE_ALLOC_H

#include <stdint.h>

#include "memory/flags.h"
#include "memory/memory.h"

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo);

// Allocate a free page frame, returning its (physical) address.  If no page
// frames are available, returns 0.
uint32_t page_frame_alloc();

// Frees the given page frame.
void page_frame_free(uint32_t frame);

// The exact same as page_frame_free, but doesn't do the extra checks (searching
// for double-free, filling with 0xDEADBEEF).  Mostly useful in tests where
// we're doing large blocks of allocations and want to avoid the overhead (since
// it can be globally disabled with a #define).
void page_frame_free_nocheck(uint32_t frame);

// Establishes a mapping from the given virtual address to the physical address
// in the currently-loaded page tables.
//
// prot should be an OR combination of MEM_PROT_* values.  access should be one
// of the MEM_ACCESS_* values.  flags should be a combination of the other mem
// flags.
//
// REQUIRES: virt and phys are page-aligned.
void page_frame_map_virtual(uint32_t virt, uint32_t phys, int prot,
                            mem_access_t access, int flags);

// Removes the mapping for the given virtual address from the currently-loaded
// page table (by marking it non-present), if it exists.
//
// REQUIRES: virt is page-aligned.
void page_frame_unmap_virtual(uint32_t virt);

#endif
