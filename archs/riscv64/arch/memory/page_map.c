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
#include <stdint.h>

#include "arch/memory/layout.h"
#include "arch/memory/page_fault.h"
#include "arch/memory/page_map.h"
#include "archs/riscv64/internal/page_tables.h"
#include "common/kassert.h"
#include "memory/page_alloc.h"

void paging_init(void) {
  // Nothing to do.
}

// Convert arch-agnostic page map flags into riscv PTE flags.
static uint64_t make_rsv_flags(int flags) {
  uint64_t rsv_flags = 0;
  if (flags & MEM_GLOBAL) rsv_flags |= RSV_PTE_GLOBAL;
  return rsv_flags;
}

void page_frame_map_virtual(addr_t virt, phys_addr_t phys, int prot,
                            mem_access_t access, int flags) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(phys % PAGE_SIZE == 0);
  KASSERT(access == MEM_ACCESS_KERNEL_ONLY ||
          access == MEM_ACCESS_KERNEL_AND_USER);
  KASSERT(flags == 0 || flags == MEM_GLOBAL);

  rsv_mapsize_t size = RSV_MAP_PAGE;
  uint64_t rsv_flags = make_rsv_flags(flags);
  rsv_sv39_pte_t* pte = rsv_get_pte(rsv_get_hart_as(), virt, &size,
                                    /* flags= */ rsv_flags, /* create= */ true);
  KASSERT(pte != NULL);
  KASSERT(size == RSV_MAP_PAGE);  // We never create large mappings today.
  if (access == MEM_ACCESS_KERNEL_ONLY && *pte & RSV_PTE_VALID) {
    // Assert that if the mapping is valid and a kernel mapping, the physical
    // addr isn't changing.  For user addresses, we do shadow memobj remapping,
    // so this doesn't apply.
    KASSERT(rsv_get_pte_addr(pte) == phys);
  }
  rsv_set_pte_addr(pte, phys, RSV_MAP_PAGE);
  *pte |= RSV_PTE_READ;
  if (prot & MEM_PROT_WRITE) *pte |= RSV_PTE_WRITE;
  if (prot & MEM_PROT_EXEC) *pte |= RSV_PTE_EXECUTE;
  if (access == MEM_ACCESS_KERNEL_AND_USER) *pte |= RSV_PTE_USER;
  *pte |= rsv_flags;
  *pte |= RSV_PTE_VALID;
  rsv_sfence();
}

void page_frame_remap_virtual(addr_t virt, int prot, mem_access_t access,
                              int flags) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(access == MEM_ACCESS_KERNEL_ONLY ||
          access == MEM_ACCESS_KERNEL_AND_USER);
  KASSERT(flags == 0 || flags == MEM_GLOBAL);

  rsv_mapsize_t size = RSV_MAP_PAGE;
  uint64_t rsv_flags = make_rsv_flags(flags);
  rsv_sv39_pte_t* pte = rsv_get_pte(rsv_get_hart_as(), virt, &size,
                                    /* flags= */ rsv_flags, /* create= */ false);
  KASSERT(pte != NULL);
  KASSERT(*pte & RSV_PTE_VALID);
  KASSERT(size == RSV_MAP_PAGE);  // Cannot remap larger sizes.
  *pte &= ~RSV_PTE_READ & ~RSV_PTE_WRITE & ~RSV_PTE_EXECUTE & ~RSV_PTE_USER &
          ~RSV_PTE_GLOBAL;
  *pte |= RSV_PTE_READ;
  if (prot & MEM_PROT_WRITE) *pte |= RSV_PTE_WRITE;
  if (prot & MEM_PROT_EXEC) *pte |= RSV_PTE_EXECUTE;
  if (access == MEM_ACCESS_KERNEL_AND_USER) *pte |= RSV_PTE_USER;
  *pte |= rsv_flags;
  rsv_sfence();
}

void page_frame_unmap_virtual(addr_t virt) {
  page_frame_unmap_virtual_range(virt, PAGE_SIZE);
}

void page_frame_unmap_virtual_range(addr_t virt, addrdiff_t length) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(length % PAGE_SIZE == 0);
  for (size_t i = 0; i < length / PAGE_SIZE; ++i) {
    // TODO(aoates): this will crash for large mappings; that can't currently
    // happen since this is only called on private mmaps, and we only use large
    // mappings for public kernel areas.  It also will fail if flags are
    // non-zero.
    rsv_mapsize_t size = RSV_MAP_PAGE;
    rsv_sv39_pte_t* pte =
        rsv_get_pte(rsv_get_hart_as(), virt + i * PAGE_SIZE, &size,
                    /* flags= */ 0, /* create= */ false);
    KASSERT(size == RSV_MAP_PAGE);
    if (pte) {
      // Mark the page as non-present.
      *pte = 0;
    }
  }
  rsv_sfence();
}

page_dir_ptr_t page_frame_alloc_directory(void) {
  phys_addr_t dir_phys = page_frame_alloc();
  KASSERT(dir_phys);
  rsv_init_page_table(dir_phys);
  return rsv_create_as(dir_phys);
}

void page_frame_free_directory(page_dir_ptr_t as) {
  // Reclaim mid-level tables.
  rsv_free_as_tables(as);

  // Free the top level.
  phys_addr_t pt_phys = rsv_get_top_page_table(as);
  KASSERT(pt_phys);
  KASSERT(pt_phys % PAGE_SIZE == 0);
  page_frame_free(pt_phys);
}

void page_frame_init_global_mapping(addr_t addr, addr_t length) {
  KASSERT(addr % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);

  // For each top-level in the current page directory, make sure a page table is
  // allocated.  This page table will be shared between all processes (by making
  // their page directories point to the same ones.
  for (size_t i = 0; i < length / MIN_GLOBAL_MAPPING_SIZE; ++i) {
    // Get the second-to-largest map size entry but don't do anything with it
    // --- this just ensures the top-level entry (which will be proactively
    // copied in link() below) exists and points to a shared entry.
    rsv_mapsize_t size = RSV_MAP_BIGGEST - 1;
    rsv_sv39_pte_t* pte = rsv_get_pte(rsv_get_hart_as(),
                                      addr + i * MIN_GLOBAL_MAPPING_SIZE, &size,
                                      /* flags= */ RSV_PTE_GLOBAL,
                                      /* create= */ true);
    KASSERT(pte != NULL);
    *pte |= RSV_PTE_GLOBAL;
  }
}

void page_frame_link_global_mapping(page_dir_ptr_t target_as,
                                    addr_t base, addr_t length) {
  // Copy all the page directory entries created in
  // page_frame_init_global_mapping() from the current address space into the
  // new page directory.
  KASSERT(base % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);

  const page_dir_ptr_t src_as = rsv_get_hart_as();
  for (size_t i = 0; i < length / MIN_GLOBAL_MAPPING_SIZE; ++i) {
    const addr_t addr = base + i * MIN_GLOBAL_MAPPING_SIZE;
    // TODO(aoates): do we want to to check or reset any of the PTE flags?
    rsv_mapsize_t size = RSV_MAP_BIGGEST;
    rsv_sv39_pte_t* source =
        rsv_get_pte(src_as, addr, &size, RSV_PTE_GLOBAL, false);
    KASSERT(source != NULL);
    KASSERT(*source & RSV_PTE_VALID);
    KASSERT(*source & RSV_PTE_GLOBAL);
    KASSERT(*source != 0);
    KASSERT_DBG(size == RSV_MAP_BIGGEST);
    rsv_sv39_pte_t* dest =
        rsv_get_pte(target_as, addr, &size, RSV_PTE_GLOBAL, false);
    KASSERT(dest != NULL);
    KASSERT(*dest == 0);
    KASSERT_DBG(size == RSV_MAP_BIGGEST);
    *dest = *source;
  }
}
