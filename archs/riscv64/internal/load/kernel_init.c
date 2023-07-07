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

#include <stddef.h>
#include <stdint.h>

#include "arch/common/debug.h"
#include "arch/common/types.h"
#include "arch/memory/layout.h"
#include "common/config.h"
#include "common/endian.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/devicetree/dtb.h"
#include "memory/memory.h"

#include "archs/riscv64/internal/page_tables.h"

_Static_assert(ARCH == ARCH_riscv64, "bad ARCH");
_Static_assert(ARCH_IS_64_BIT, "ARCH_IS_64_BIT should be set");

extern void kmain(memory_info_t* meminfo);

// Can't use phys2virt yet, since we haven't set up the global meminfo.
static addr_t init_phys2virt(phys_addr_t phys) {
  return phys + RSV64_KPHYSMAP_ADDR;
}

static void setup_kernel_mappings(void) {
  phys_addr_t top_pt_addr = rsv_get_top_page_table();
  // Access it through its physical address for now.
  rsv_sv39_pte_t* top_pt = (rsv_sv39_pte_t*)top_pt_addr;

  // Create the physical page map -- after this, we should only reference memory
  // through this mapping.
  _Static_assert(RSV64_KPHYSMAP_ADDR % RSV_MAP_GIGAPAGE_SIZE == 0, "");
  _Static_assert(RSV64_KPHYSMAP_LEN % RSV_MAP_GIGAPAGE_SIZE == 0, "");
  size_t first_physmap = rsv_pte_index(RSV64_KPHYSMAP_ADDR, RSV_MAP_GIGAPAGE);
  size_t last_physmap = rsv_pte_index(
      RSV64_KPHYSMAP_ADDR + (RSV64_KPHYSMAP_LEN - 1), RSV_MAP_GIGAPAGE);
  KASSERT(first_physmap < 512);
  KASSERT(last_physmap < 512);
  KASSERT(last_physmap - first_physmap + 1 ==
          RSV64_KPHYSMAP_LEN / RSV_MAP_GIGAPAGE_SIZE);
  for (size_t i = first_physmap; i <= last_physmap; ++i) {
    // TODO(aoates): this should probably be volatile.
    rsv_sv39_pte_t* pte = &top_pt[i];
    KASSERT(*pte == 0x0);
    phys_addr_t mapped = (i - first_physmap) * RSV_MAP_GIGAPAGE_SIZE;
    rsv_set_pte_addr(pte, mapped, RSV_MAP_GIGAPAGE);
    *pte |= RSV_PTE_GLOBAL | RSV_PTE_READ | RSV_PTE_WRITE;
    *pte |= RSV_PTE_VALID;
  }

  rsv_sfence();

  // Now undo the identity mapping we set up in loader.s.
  top_pt_addr = init_phys2virt(top_pt_addr);
  top_pt = (rsv_sv39_pte_t*)top_pt_addr;
  const phys_addr_t KERNEL_PHYS_ADDR = 0x0000000080000000;
  size_t idx = rsv_pte_index(KERNEL_PHYS_ADDR, RSV_MAP_GIGAPAGE);
  rsv_sv39_pte_t* pte = &top_pt[idx];
  // Sanity check we got the right one.
  KASSERT(top_pt[idx - 1] == 0);
  KASSERT(top_pt[idx + 1] == 0);
  KASSERT(*pte & RSV_PTE_VALID);
  KASSERT((*pte >> 10) << 12 == KERNEL_PHYS_ADDR);
  *pte = 0;
  rsv_sfence();
}

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.
void kinit(int hart_id, phys_addr_t fdt_phys) {
  setup_kernel_mappings();

  klog("Booting APOS on riscv64\n");

  const void* fdt = (const void*)init_phys2virt(fdt_phys);
  if (dtfdt_print(fdt, true, &klog) != 0) {
    die("Bad FDT passed in");
  }

  // We can't ever return or we'll page fault!
  while(1);
}
