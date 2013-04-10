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

#ifndef APOO_PAGING_H
#define APOO_PAGING_H

#include <stdint.h>

#include "load/multiboot.h"
#include "memory/memory.h"

// The VMA offset at which we're loading our kernel.  We can subtract this from
// KERNEL_{START,END}_SYMBOL to get the physical limits of the kernel as loaded
// by GRUB.  Note that the kernel will actually be loaded 1MB past this by GRUB.
//
// Note: keep this is sync with the constant in linker.ld.
#define KERNEL_VIRT_START 0xC0000000

// Initialize page tables and enable paging.
//
// Identity maps the first 4MB of memory.  Must be called before paging has been
// enabled, and linked at it's physical address.
//
// Takes the PHYSICAL address of the multiboot info structure provided by GRUB,
// and returns the VIRTUAL address of a memory_info_t that has been allocated
// and filled.
//
// Once this returns, we are running in virtual memory.
memory_info_t* mem_init(uint32_t magic, multiboot_info_t* multiboot_info_phys,
                        uint32_t stack);

#endif
