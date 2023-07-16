// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

// Internal riscv64-specific utilities for manipulating page tables.
#ifndef APOO_ARCHS_RISCV64_INTERNAL_PAGE_TABLES_H
#define APOO_ARCHS_RISCV64_INTERNAL_PAGE_TABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "arch/common/types.h"
#include "arch/memory/layout.h"
#include "memory/memory.h"

// These are independent of XLEN and paging mode --- all PTEs use these bits.
#define RSV_PTE_VALID 0x1
#define RSV_PTE_READ 0x2
#define RSV_PTE_WRITE 0x4
#define RSV_PTE_EXECUTE 0x8
#define RSV_PTE_USER 0x10
#define RSV_PTE_GLOBAL 0x20
#define RSV_PTE_ACCESSED 0x40
#define RSV_PTE_DIRTY 0x80
// ...then 2 RSW bits we don't use

// Masks/offsets for the virtual page number (VPN) fields in a virtual address.
#define RSV_SV39_VPAGE_OFFSET 0
#define RSV_SV39_VPAGE_MASK 0xFFF
#define RSV_SV39_VPN0_OFFSET 12
#define RSV_SV39_VPN0_MASK (0x1FFul << RSV_SV39_VPN0_OFFSET)
#define RSV_SV39_VPN1_OFFSET 21
#define RSV_SV39_VPN1_MASK (0x1FFul << RSV_SV39_VPN1_OFFSET)
#define RSV_SV39_VPN2_OFFSET 30
#define RSV_SV39_VPN2_MASK (0x1FFul << RSV_SV39_VPN2_OFFSET)
// Bits 39 and above must be the same as bit 38.

#define RSV_SV39_PTESIZE 8
#define RSV_SV39_PTENTRIES 512
_Static_assert(RSV_SV39_PTENTRIES == PAGE_SIZE / RSV_SV39_PTESIZE, "");

#define SATP64_PPN_MASK 0x00000FFFFFFFFFFF

typedef uint64_t rsv_sv39_pte_t;

// Sizes of mappings available.
typedef enum {
  RSV_MAP_PAGE = 0,
  RSV_MAP_MEGAPAGE = 1,
  RSV_MAP_GIGAPAGE = 2,
} rsv_mapsize_t;

#define RSV_MAP_SMALLEST RSV_MAP_PAGE
#define RSV_MAP_BIGGEST RSV_MAP_GIGAPAGE

#define RSV_MAP_PAGESIZE PAGE_SIZE
#define RSV_MAP_MEGAPAGE_SIZE (PAGE_SIZE << 9)  // 2 MiB
#define RSV_MAP_GIGAPAGE_SIZE (PAGE_SIZE << 18) // 1 GiB
_Static_assert(MIN_GLOBAL_MAPPING_SIZE == RSV_MAP_GIGAPAGE_SIZE,
               "MIN_GLOBAL_MAPPING_SIZE doesn't match gigapage size");

// Returns the address space of the current HART.
page_dir_ptr_t rsv_get_hart_as(void);

// Returns the physical address of the current HART's first page table.
phys_addr_t rsv_get_top_page_table(void);

// Return a pointer to the PTE for the given mapping in the given address space
// with the given size.  The virtual address must be aligned to the requested
// mapsize.  If |create| is true, intermediate page tables will be allocated as
// needed.
//
// Newly created entries are zeroed; the caller must fill in the bits as
// necessary.
//
// If page tables exist below the requested size (i.e., a mapping for this
// address, or a different address in the requested mapping size), the
// non-terminal PTE at the requested size is returned --- the caller must check.
//
// For example, rsv_get_pte(RSV_MAP_SMALLEST) will always return the existing
// mapping, whatever its size (or the final PTE).  rsv_get_pte(RSV_MAP_BIGGEST)
// will always return the top-level PTE.
//
// The mapping itself is _not_ created, only the intermediate data structures
// necessary to get to a final PTE for the given mapsize --- the caller could
// create a mapping of that size, or a different size if the returned PTE is
// empty.
//
// If succesful, returns a pointer to the PTE.  If the necessary page tables.
// don't exist and |create| is false, returns an error.  Likewise, if
// intermediate page tables cannot be allocated, fails.
rsv_sv39_pte_t* rsv_get_pte(page_dir_ptr_t as, addr_t virt, rsv_mapsize_t* size,
                            bool create);

// Similar to rsv_get_page(), but just returns the lowest available PTE for the
// given address.  Will not create any entries.
rsv_sv39_pte_t rsv_lookup_pte(page_dir_ptr_t as, addr_t virt,
                              rsv_mapsize_t* size_out);

// Issue a local sfence.vma instruction.
void rsv_sfence(void);

// Low-level utilities exposed for use during boot before VM is fully set up.

// Sets the mapping on the given PTE.  The physical address and virtual address
// must both be aligned to the requested size.
void rsv_set_pte_addr(rsv_sv39_pte_t* pte, phys_addr_t phys,
                      rsv_mapsize_t size);

// Returns the index of the virtual address in the page table at the given level
size_t rsv_pte_index(addr_t virt, rsv_mapsize_t level);

// Initialize (and empty) the given page table.
void rsv_init_page_table(phys_addr_t pt);

#endif
