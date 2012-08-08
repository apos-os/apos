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

// Basic data structures and constants used by the lowel-level memory code.
#ifndef APOO_MEMORY_H
#define APOO_MEMORY_H

#include <stdint.h>

#define PAGE_SIZE          0x00001000
#define PAGE_INDEX_MASK    0xFFFFF000
#define PAGE_OFFSET_MASK   0x00000FFF

#define PDE_ADDRESS_MASK   0xFFFFF000 /* PAGE_INDEX_MASK */
#define PDE_LARGE_PAGES    0x00000080
#define PDE_ACCESSED       0x00000020
#define PDE_CACHE_DISABLED 0x00000010
#define PDE_WRITE_THROUGH  0x00000008
#define PDE_USER_ACCESS    0x00000004
#define PDE_WRITABLE       0x00000002
#define PDE_PRESENT        0x00000001
#define PDE_NUM_ENTRIES    (PAGE_SIZE / 4)

#define PTE_ADDRESS_MASK   0xFFFFF000 /* PAGE_INDEX_MASK */
#define PTE_GLOBAL         0x00000100
#define PTE_DIRTY          0x00000040
#define PTE_ACCESSED       0x00000020
#define PTE_CACHE_DISABLED 0x00000010
#define PTE_WRITE_TRHOUGH  0x00000008
#define PTE_USER_ACCESS    0x00000004
#define PTE_WRITABLE       0x00000002
#define PTE_PRESENT        0x00000001
#define PTE_NUM_ENTRIES    (PAGE_SIZE / 4)

// A structure generated by load/mem_init.c that describes the layout of virtual
// memory, how much of the kernel is mapped (and where), and what physical pages
// have been allocated thus far.
typedef struct {
  // The physical and virtual addresses of the kernel start and end.
  uint32_t kernel_start_phys;
  uint32_t kernel_end_phys;

  uint32_t kernel_start_virt;
  uint32_t kernel_end_virt;

  // The area of virtual memory that has been mapped for use by the kernel.
  uint32_t mapped_start;
  uint32_t mapped_end;

  // The amount of lower (<1MB) and upper (>1MB) memory available on the
  // machine, in bytes.
  uint32_t lower_memory;
  uint32_t upper_memory;

  // The location in kernel memory at which the lowest portion of physical
  // memory is mapped.  Any physical address in that region can be accessed by
  // adding this offset to get the corresponding virtual address.
  uint32_t phys_map_start;

  // The size of the physically-mapped region.  If there is too much physical
  // memory to fit in the virtual map region, only the lowest X bytes will be
  // mapped.
  uint32_t phys_map_length;

  // Start and end (virtual) addresses of the  kernel heap.  The heap consists
  // of memory in the range [heap_start, heap_end).
  // TODO(aoates): once we have a better VM system set up, use a memory map for
  // this rather than a pseudo-hard-coded range.
  uint32_t heap_start;
  uint32_t heap_end;
} memory_info_t;

// Once we've finished setting up our initial memory mappings, sets a global
// memory_info_t that is used by the other functions in this module.
void set_global_meminfo(memory_info_t* meminfo);

const memory_info_t* get_global_meminfo();

// Returns the page containing the given address.
uint32_t addr2page(uint32_t addr);

// Returns the next page/frame start address after x (or x if x is
// page-aligned).
uint32_t next_page(uint32_t x);

// Returns non-zero if the given address is page-aligned.
int is_page_aligned(uint32_t x);

// Converts a physical address to a virtual address (i.e. the virtual location,
// in the kernel's space, where that physical page is mapped, at
// meminfo->phys_map_start).
uint32_t phys2virt(uint32_t x);

// Converts a virtual address (in the direct-mapped region) to the corresponding
// physical address.
uint32_t virt2phys(uint32_t x);

// Returns true if the address is a physical address mapped into the
// direct-mapped region (that is, if phys2virt would succeed).
int is_direct_mappable(uint32_t x);

// Returns true if the address is a VIRTUAL address IN the
// direct-mapped region (that is, if virt2phys would succeed).
int is_direct_mapped(uint32_t x);

// Converts a physical address IN THE KERNEL to a virtual address IN THE KERNEL
// (i.e.  the virtual location, in the kernel, where that physical page is
// mapped, at 0xc0000000).
//
// This differs from phys2virt in that it only works on addresses in the
// physical kernel loaded at boot, not arbitrary physical addresses.
uint32_t phys2kernel(uint32_t x);

#endif
