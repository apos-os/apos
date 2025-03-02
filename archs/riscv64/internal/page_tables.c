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
#include "archs/riscv64/internal/page_tables.h"

#include <stdint.h>

#include "arch/common/types.h"
#include "arch/memory/layout.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "vfs/vnode.h"

#define phys2ppn(x) (x / PAGE_SIZE)
#define ppn2phys(x) (x * PAGE_SIZE)
#define vpn2virt(x) (x * PAGE_SIZE)

// The 44-bit physical page number fields.
#define RSV_SV39_PTE_PPN0_OFFSET 10
#define RSV_SV39_PTE_PPN0_MASK (0x1FFul << RSV_SV39_PTE_PPN0_OFFSET)
#define RSV_SV39_PTE_PPN1_OFFSET 19
#define RSV_SV39_PTE_PPN1_MASK (0x1FFul << RSV_SV39_PTE_PPN1_OFFSET)
#define RSV_SV39_PTE_PPN2_OFFSET 28
#define RSV_SV39_PTE_PPN2_MASK (0x3FFFFFFul << RSV_SV39_PTE_PPN1_OFFSET)
#define RSV_SV39_PTE_PPN_MASK \
  (RSV_SV39_PTE_PPN0_MASK | RSV_SV39_PTE_PPN1_MASK | RSV_SV39_PTE_PPN2_MASK)
#define RSV_SV39_PTE_PPN_OFFSET RSV_SV39_PTE_PPN0_OFFSET

#define RSV_SATP_MODE_SV39 (8ull << 60)
#define RSV_SATP_PPN(satp) ((satp) & 0xFFFFFFFFFFF)

// We use the same indexing scheme as the virtual address breakdown --- pte2 is
// the top-level PTE (corresponding to VPN2), etc.

static bool is_valid(rsv_sv39_pte_t pte) {
  return pte & RSV_PTE_VALID;
}

static bool is_terminal(rsv_sv39_pte_t pte) {
  if (!is_valid(pte)) return false;
  const uint64_t rwx_bits =
      pte & (RSV_PTE_READ | RSV_PTE_WRITE | RSV_PTE_EXECUTE);
  if (rwx_bits != 0) {
    // We only generate readable pages currently, no execute-only.
    KASSERT_DBG(pte & RSV_PTE_READ);
    return true;
  }
  return false;
}

size_t rsv_pte_index(addr_t virt, rsv_mapsize_t level) {
  uint64_t pte_idx = (virt >> (12 + 9 * level)) & 0x01FF;
  KASSERT_DBG(pte_idx < RSV_SV39_PTENTRIES);
  return pte_idx;
}

// Given the PPN of a page table (from satp, or a previous PTE) and a virtual
// address, return a pointer to that address's PTE in that table.
static rsv_sv39_pte_t* get_pte_from_ppn(uint64_t table_ppn, addr_t virt,
                                        int level) {
  phys_addr_t table_phys = ppn2phys(table_ppn);
  rsv_sv39_pte_t* table = (rsv_sv39_pte_t*)phys2virt(table_phys);
  size_t pte_idx = rsv_pte_index(virt, level);
  return &table[pte_idx];
}

static rsv_sv39_pte_t* get_next_pte(rsv_sv39_pte_t pte, addr_t virt,
                                    int level) {
  KASSERT_DBG(is_valid(pte));
  KASSERT_DBG(!is_terminal(pte));
  uint64_t next_pt_ppn =
      (pte & RSV_SV39_PTE_PPN_MASK) >> RSV_SV39_PTE_PPN_OFFSET;
  return get_pte_from_ppn(next_pt_ppn, virt, level);
}

static uint64_t get_mapsize(rsv_mapsize_t sz) {
  switch (sz) {
    case RSV_MAP_PAGE:
      return RSV_MAP_PAGESIZE;
    case RSV_MAP_MEGAPAGE:
      return RSV_MAP_MEGAPAGE;
    case RSV_MAP_GIGAPAGE:
      return RSV_MAP_GIGAPAGE_SIZE;
  }
  die("unknown rsv_mapsize_t");
}

static int mapsize_level(rsv_mapsize_t sz) {
  return (int)sz;
}

void rsv_init_page_table(phys_addr_t pt_phys) {
  KASSERT_DBG(pt_phys % PAGE_SIZE == 0);
  kmemset((void*)phys2virt(pt_phys), 0, PAGE_SIZE);
}

page_dir_ptr_t rsv_get_hart_as(void) {
  uint64_t satp;
  asm volatile("csrr %0, satp" : "=r"(satp)::);
  return satp;
}

phys_addr_t rsv_get_top_page_table(page_dir_ptr_t as) {
  phys_addr_t ppn = RSV_SATP_PPN(as);
  KASSERT_DBG(as == (ppn | RSV_SATP_MODE_SV39));  // No ASIDs today.
  return ppn2phys(ppn);
}

page_dir_ptr_t rsv_create_as(phys_addr_t pt_phys) {
  KASSERT(pt_phys % PAGE_SIZE == 0);
  // No ASID support today.
  return RSV_SATP_MODE_SV39 | phys2ppn(pt_phys);
}

#define RSV_SV39_LEVELS 3

// TODO(riscv): write tests for this for all possible combinations:
//  - non-existing mapping (created all the way down)
//  - non-existing mapping but intermediate partially exists
//  - non-existing mapping but intermediate partially exists (and extends
//    "lower" than requested)
//  - existing mappings of smaller, equal, and larger than requested sizes.
rsv_sv39_pte_t* rsv_get_pte(page_dir_ptr_t as, addr_t virt, rsv_mapsize_t* size,
                            uint64_t flags, bool create) {
  KASSERT((flags & ~RSV_GET_PTE_VALID_FLAGS) == 0);
  const uint64_t mapsize_bytes = get_mapsize(*size);
  KASSERT(virt % mapsize_bytes == 0);

  // Based on the lookup loop described in section 4.3.2 of the privileged spec.
  uint64_t pt_ppn = RSV_SATP_PPN(as);
  int level = RSV_SV39_LEVELS - 1;
  int final_level = mapsize_level(*size);
  KASSERT_DBG(final_level <= level);
  rsv_sv39_pte_t* pte = get_pte_from_ppn(pt_ppn, virt, level);
  while (level > final_level && !is_terminal(*pte)) {
    // Create a new page table if required.
    if (!is_valid(*pte)) {
      if (!create) return NULL;

      phys_addr_t new_pt = page_frame_alloc();
      if (!new_pt) return NULL;
      rsv_init_page_table(new_pt);
      // Make the PTE point at the new page table.
      *pte = 0;
      rsv_set_pte_addr(pte, new_pt, RSV_MAP_PAGE);
      *pte |= RSV_PTE_VALID;
      *pte |= flags;
      // Leave DAU and RWX as zero since this is a non-leaf.
    } else {
      // We must match flags all the way down.
      KASSERT((*pte & RSV_GET_PTE_VALID_FLAGS) == flags);
    }

    level--;
    pte = get_next_pte(*pte, virt, level);
  }
  // Sanity check --- final-level PTEs should always be invalid or terminal.
  if (level == 0) {
    KASSERT_DBG(!is_valid(*pte) || is_terminal(*pte));
  }
  *size = level;
  return pte;
}

rsv_sv39_pte_t rsv_lookup_pte(page_dir_ptr_t as, addr_t virt,
                              rsv_mapsize_t* size_out) {
  // Based on the lookup loop described in section 4.3.2 of the privileged spec.
  uint64_t pt_ppn = RSV_SATP_PPN(as);
  int level = RSV_SV39_LEVELS - 1;
  rsv_sv39_pte_t* pte = get_pte_from_ppn(pt_ppn, virt, level);
  while (is_valid(*pte) && level > 0) {
    const uint64_t rwx_bits =
        *pte & (RSV_PTE_READ | RSV_PTE_WRITE | RSV_PTE_EXECUTE);
    if (rwx_bits != 0) {
      // Found a terminal large-size PTE.
      break;
    }
    level--;
    pte = get_next_pte(*pte, virt, level);
  }
  *size_out = level;
  return *pte;
}

void rsv_set_pte_addr(rsv_sv39_pte_t* pte, phys_addr_t phys,
                      rsv_mapsize_t size) {
  const uint64_t mapsize_bytes = get_mapsize(size);
  KASSERT(phys % mapsize_bytes == 0);
  *pte &= ~RSV_SV39_PTE_PPN_MASK;  // Zero the current PPN.
  uint64_t ppn = phys / PAGE_SIZE;
  uint64_t offset_ppn = (ppn << RSV_SV39_PTE_PPN_OFFSET);
  // Sanity check.
  KASSERT_DBG((offset_ppn & RSV_SV39_PTE_PPN_MASK) == offset_ppn);
  *pte |= offset_ppn;
}

phys_addr_t rsv_get_pte_addr(const rsv_sv39_pte_t* pte) {
  KASSERT(*pte & RSV_PTE_VALID);
  return ((*pte & RSV_SV39_PTE_PPN_MASK) >> RSV_SV39_PTE_PPN_OFFSET) *
         PAGE_SIZE;
}

void rsv_sfence(void) {
  asm volatile ("sfence.vma");
}
