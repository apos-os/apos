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

// We use the same indexing scheme as the virtual address breakdown --- pte2 is
// the top-level PTE (corresponding to VPN2), etc.

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
  KASSERT_DBG(pte & RSV_PTE_VALID);
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

static void init_page_table(phys_addr_t pt_phys) {
  kmemset((void*)phys2virt(pt_phys), 0, PAGE_SIZE);
}

page_dir_ptr_t rsv_get_hart_as(void) {
  uint64_t pt2_ppn;
  asm volatile("csrr %0, satp" : "=r"(pt2_ppn)::);
  pt2_ppn = pt2_ppn & SATP64_PPN_MASK;  // No shift needed.
  return pt2_ppn;
}

phys_addr_t rsv_get_top_page_table(void) {
  page_dir_ptr_t pt_ppn = rsv_get_hart_as();
  return ppn2phys(pt_ppn);
}

#define RSV_SV39_LEVELS 3

rsv_sv39_pte_t* rsv_get_pte(page_dir_ptr_t as, addr_t virt, rsv_mapsize_t size,
                            bool create) {
  const uint64_t mapsize_bytes = get_mapsize(size);
  KASSERT(virt % mapsize_bytes == 0);

  // Based on the lookup loop described in section 4.3.2 of the privileged spec.
  uint64_t pt_ppn = as;
  int level = RSV_SV39_LEVELS - 1;
  int final_level = (int)size;
  KASSERT_DBG(final_level <= level);
  rsv_sv39_pte_t* pte = get_pte_from_ppn(pt_ppn, virt, level);
  while (level > final_level) {
    // Create a new page table if required.
    if (!(*pte & RSV_PTE_VALID)) {
      if (!create) return NULL;

      phys_addr_t new_pt = page_frame_alloc();
      if (!new_pt) return NULL;
      init_page_table(new_pt);
      // Make the PTE point at the new page table.
      *pte = 0;
      rsv_set_pte_addr(pte, new_pt, RSV_MAP_PAGE);
      *pte |= RSV_PTE_VALID;
      // Leave DAU and RWX as zero since this is a non-leaf.
      // TODO(aoates): support global mappings --- will require a bit to
      // indicate whether the mapping should be global all the way down, or only
      // on the final table.
    }

    KASSERT_DBG(*pte & RSV_PTE_VALID);
    const uint64_t rwx_bits =
        *pte & (RSV_PTE_READ | RSV_PTE_WRITE | RSV_PTE_EXECUTE);
    if (rwx_bits != 0) {
      // Found a terminal PTE even though we're searching for a smaller mapping.
      // Simply die.  If we want to support this, would need to remap the
      // addresses into a new page table (expand the mapping).
      // Currently non-leaf PTEs are used sparingly and statically by the
      // kernel only, so not an issue.
      die("found leaf PTE at wrong level");
    }
    level--;
    pte = get_next_pte(*pte, virt, level);
  }
  return pte;
}

rsv_sv39_pte_t rsv_lookup_pte(page_dir_ptr_t as, addr_t virt,
                              rsv_mapsize_t* size_out) {
  // Based on the lookup loop described in section 4.3.2 of the privileged spec.
  uint64_t pt_ppn = as;
  int level = RSV_SV39_LEVELS - 1;
  rsv_sv39_pte_t* pte = get_pte_from_ppn(pt_ppn, virt, level);
  while ((*pte & RSV_PTE_VALID) && level > 0) {
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

void rsv_sfence(void) {
  asm volatile ("sfence.vma");
}
