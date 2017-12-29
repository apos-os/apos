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

// Code for the low-level kernel page frame allocator, which is responsible for
// allocating physical pages.

#ifndef APOO_ARCHS_COMMON_ARCH_MEMORY_PAGE_ALLOC_H
#define APOO_ARCHS_COMMON_ARCH_MEMORY_PAGE_ALLOC_H

#include <stddef.h>
#include <stdint.h>

#include "common/types.h"
#include "memory/flags.h"
#include "memory/memory.h"

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo);

// Allocate a free page frame, returning its (physical) address.  If no page
// frames are available, returns 0.
phys_addr_t page_frame_alloc(void);

// Frees the given page frame.
void page_frame_free(phys_addr_t frame);

// The exact same as page_frame_free, but doesn't do the extra checks (searching
// for double-free, filling with 0xDEADBEEF).  Mostly useful in tests where
// we're doing large blocks of allocations and want to avoid the overhead (since
// it can be globally disabled with a #define).
void page_frame_free_nocheck(phys_addr_t frame);

// Allocates a continuous block of N pages that is suitable for DMA usage by
// device drivers.  Returns the first frame in the block, or 0 if unable.
// TODO(aoates): design a more flexible memory allocation system to support
// this natively.
phys_addr_t page_frame_dma_alloc(size_t pages);

#endif
