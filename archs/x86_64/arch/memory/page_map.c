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
#include "arch/memory/page_map.h"
#include "archs/x86_64/internal/memory/page_tables.h"
#include "common/kassert.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"

#define SUPPORTS_INVPLG_INSTRUCTION 0

typedef addr_t pte_t;
typedef addr_t pde_t;
typedef addr_t pdpte_t;
typedef addr_t pml4e_t;

// Returns the current page directory.
static inline pml4e_t* get_pml4(void) {
  uint64_t cr3;
  asm volatile ("movq %%cr3, %0" : "=r"(cr3));
  return (pml4e_t*)phys2virt(cr3);
}

// Invalidate the TLB entry for the given virtual address.
static inline void invalidate_tlb(addr_t virt) {
  _Static_assert(sizeof(virt) == sizeof(uint64_t), "Not 64-bit");
  if (SUPPORTS_INVPLG_INSTRUCTION) {
    asm volatile (
        "invlpg %0\n\t"
        :: "m"(virt));
  } else {
    asm volatile (
        "mov %%cr3, %%rax\n\t"
        "mov %%rax, %%cr3\n\t"
        ::: "rax");
  }
}

// Given a virtual page address, returns a pointer to the page table entry
// responsible for page.  If create is non-zero, and the page table doesn't
// exist, a page table is allocated and initialized for it.
static pte_t* get_or_create_page_table_entry(addr_t virt, bool create, int prot,
                                             mem_access_t access,
                                             int mapping_flags) {
  _Static_assert(PML4_NUM_ENTRIES == PDPT_NUM_ENTRIES &&
                 PML4_NUM_ENTRIES == PD_NUM_ENTRIES &&
                 PML4_NUM_ENTRIES == PT_NUM_ENTRIES, "bad pagetable constants");
  _Static_assert(PML4E_PRESENT == PDPTE_PRESENT &&
                 PML4E_PRESENT == PDE_PRESENT &&
                 PML4E_PRESENT == PTE_PRESENT, "bad pagetable constants");
  _Static_assert(PML4E_PRESENT == PDPTE_PRESENT &&
                 PML4E_PRESENT == PDE_PRESENT &&
                 PML4E_PRESENT == PTE_PRESENT, "bad pagetable constants");
  _Static_assert(PML4E_ADDRESS_MASK == PDPTE_ADDRESS_MASK &&
                 PML4E_ADDRESS_MASK == PDE_ADDRESS_MASK &&
                 PML4E_ADDRESS_MASK == PTE_ADDRESS_MASK,
                 "bad pagetable constants");
  _Static_assert(PML4E_WRITABLE == PDPTE_WRITABLE &&
                 PML4E_WRITABLE == PDE_WRITABLE &&
                 PML4E_WRITABLE == PTE_WRITABLE, "bad pagetable constants");
  _Static_assert(PML4E_USER_ACCESS == PDPTE_USER_ACCESS &&
                 PML4E_USER_ACCESS == PDE_USER_ACCESS &&
                 PML4E_USER_ACCESS == PTE_USER_ACCESS,
                 "bad pagetable constants");
  _Static_assert(PDPTE_GLOBAL == PDE_GLOBAL &&
                 PDPTE_GLOBAL == PTE_GLOBAL, "bad pagetable constants");
  pml4e_t* pml4 = get_pml4();
  KASSERT(virt % PAGE_SIZE == 0);

  const uint64_t entry_flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER_ACCESS;

  // Mask out the leading bits of the canonicalized address, then calculate
  // indices (from the start of memory).
  uint64_t page_idx = ((virt & VIRT_ADDR_MASK) / PAGE_SIZE);
  uint64_t pt_idx = page_idx / PT_NUM_ENTRIES;
  uint64_t pd_idx = pt_idx / PD_NUM_ENTRIES;
  uint64_t pdpt_idx = pd_idx / PDPT_NUM_ENTRIES;
  KASSERT(pdpt_idx < PML4_NUM_ENTRIES);

  addr_t* ctbl = pml4;
  const uint64_t indexes[3] = {pdpt_idx, pd_idx, pt_idx};
  const uint64_t flags_mask[3] = {PDPTE_GLOBAL, 0, 0};
  for (int level = 0; level < 3; ++level) {
    if ((ctbl[indexes[level] % PML4_NUM_ENTRIES] & PML4E_PRESENT) == 0) {
      if (!create) return NULL;
      phys_addr_t tbl_phys_addr = page_frame_alloc();
      KASSERT(tbl_phys_addr);
      KASSERT_DBG((tbl_phys_addr & PML4E_ADDRESS_MASK) == tbl_phys_addr);
      addr_t* tbl = (addr_t*)phys2virt(tbl_phys_addr);
      for (int i = 0; i < PDPT_NUM_ENTRIES; ++i) {
        tbl[i] = 0;
      }
      ctbl[indexes[level] % PML4_NUM_ENTRIES] = tbl_phys_addr |
          (entry_flags & ~flags_mask[level]);
      ctbl = tbl;
    } else {
      ctbl = (addr_t*)phys2virt(ctbl[indexes[level] % PML4_NUM_ENTRIES]
                                & PDPTE_ADDRESS_MASK);
      KASSERT_DBG((addr_t)ctbl % PAGE_SIZE == 0);
    }
  }

  return &ctbl[page_idx % PT_NUM_ENTRIES];
}

// TODO(aoates): make kernel mappings PDE_GLOBAL for efficiency.
void page_frame_map_virtual(addr_t virt, phys_addr_t phys, int prot,
                            mem_access_t access, int flags) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(phys % PAGE_SIZE == 0);
  KASSERT(access == MEM_ACCESS_KERNEL_ONLY ||
          access == MEM_ACCESS_KERNEL_AND_USER);
  KASSERT(flags == 0 || flags == MEM_GLOBAL);

  // The PDE entry we may create will automatically get the most permissive
  // flags.
  pte_t* pte = get_or_create_page_table_entry(virt, true, prot, access, flags);
  // TODO(aoates): plumb through an "allow overwrite" bit, and KASSERT that the
  // PTE_PRESENT flag is unset if that bit is false.
  *pte = phys | PTE_PRESENT;
  if (prot & MEM_PROT_WRITE) *pte |= PTE_WRITABLE;
  if (access == MEM_ACCESS_KERNEL_AND_USER) *pte |= PTE_USER_ACCESS;
  if (flags & MEM_GLOBAL) *pte |= PTE_GLOBAL;
  invalidate_tlb(virt);
}

void page_frame_remap_virtual(addr_t virt, int prot, mem_access_t access,
                              int flags) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(access == MEM_ACCESS_KERNEL_ONLY ||
          access == MEM_ACCESS_KERNEL_AND_USER);
  KASSERT(flags == 0 || flags == MEM_GLOBAL);

  pte_t* pte = get_or_create_page_table_entry(virt, false, prot, access, flags);
  KASSERT(pte != NULL);
  KASSERT(*pte | PTE_PRESENT);
  *pte &= ~PTE_WRITABLE & ~PTE_USER_ACCESS & ~PTE_GLOBAL;
  if (prot & MEM_PROT_WRITE) *pte |= PTE_WRITABLE;
  if (access == MEM_ACCESS_KERNEL_AND_USER) *pte |= PTE_USER_ACCESS;
  if (flags & MEM_GLOBAL) *pte |= PTE_GLOBAL;
  invalidate_tlb(virt);
}

void page_frame_unmap_virtual(addr_t virt) {
  page_frame_unmap_virtual_range(virt, PAGE_SIZE);
}

void page_frame_unmap_virtual_range(addr_t virt, addrdiff_t length) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(length % PAGE_SIZE == 0);
  for (size_t i = 0; i < length / PAGE_SIZE; ++i) {
    pte_t* pte = get_or_create_page_table_entry(virt + i * PAGE_SIZE,
                                                false, 0, 0, 0);
    if (pte) {
      // Mark the page as non-present.
      *pte = 0;
      invalidate_tlb(virt);
      // TODO(aoates): walk up the page hierarchy and claim empty mid-level
      // tables.
    }
  }
}

page_dir_ptr_t page_frame_alloc_directory() {
  phys_addr_t dir_phys = page_frame_alloc();
  KASSERT(dir_phys);
  KASSERT_DBG((dir_phys & PML4E_ADDRESS_MASK) == dir_phys);

  pde_t* dir = (pde_t*)phys2virt(dir_phys);
  for (size_t i = 0; i < PML4_NUM_ENTRIES; ++i) {
    dir[i] = 0;
  }

  // Map shared kernel PDPT at end.
  pml4e_t* pml4 = get_pml4();
  dir[PML4_NUM_ENTRIES - 1] = pml4[PML4_NUM_ENTRIES - 1];

  return dir_phys;
}

void page_frame_free_directory(page_dir_ptr_t page_directory) {
  KASSERT(page_directory);
  KASSERT(page_directory % PAGE_SIZE == 0);
  // TODO(aoates): reclaim mid-level tables.
  page_frame_free(page_directory);
}

void page_frame_init_global_mapping(addr_t addr, addr_t length) {
  KASSERT(addr % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);
  // TODO(aoates): assert in shared kernel region.
}

void page_frame_link_global_mapping(page_dir_ptr_t target,
                                    addr_t addr, addr_t length) {
  KASSERT(addr % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);
  // TODO(aoates): assert in shared kernel region.
}
