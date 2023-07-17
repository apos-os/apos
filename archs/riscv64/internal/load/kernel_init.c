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
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/dtb.h"
#include "memory/memory.h"

#include "archs/riscv64/internal/page_tables.h"

_Static_assert(ARCH == ARCH_riscv64, "bad ARCH");
_Static_assert(ARCH_IS_64_BIT, "ARCH_IS_64_BIT should be set");

extern int KERNEL_START_SYMBOL, KERNEL_END_SYMBOL;
extern void kmain(memory_info_t* meminfo);

static memory_info_t g_meminfo;

// Can't use phys2virt yet, since we haven't set up the global meminfo.
static addr_t init_phys2virt(phys_addr_t phys) {
  return phys + RSV64_KPHYSMAP_ADDR;
}

// Finds the first "memory" node and uses it.
// TODO(aoates): generate and use a proper multi-block memory map.  Also, do
// this more flexibly --- this is very brittle.
static int find_memory_node(const dt_tree_t* fdt, uint64_t* addr_out,
                            uint64_t* len_out) {
  dt_node_t* child = fdt->root->children;
  while (child) {
    if (kstr_startswith(child->name, "memory@")) break;
    child = child->next;
  }
  if (!child) {
    klog("Unable to find /memory@XXX FDT node\n");
    return -1;
  }

  // Find the reg property.
  const dt_property_t* reg = dt_get_prop(child, "reg");
  if (!reg) {
    klogf("/%s node has no 'reg' property\n", child->name);
    return -1;
  }

  if (child->context.address_cells != 2 || child->context.size_cells != 2) {
    klog("Unexpected FDT #address-cells or #size-cells\n");
    return false;
  }
  if (reg->val_len != 2 * sizeof(uint64_t)) {
    klog("Unable to handle more than one memory range\n");
    return false;
  }
  const uint64_t* cells = (uint64_t*)reg->val;
  *addr_out = btoh64(cells[0]);
  *len_out = btoh64(cells[1]);
  return 0;
}

#define INIT_FDT_BUFLEN 20000
static char g_fdt_buf[INIT_FDT_BUFLEN];

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
  size_t idx = rsv_pte_index(RSV64_KERNEL_PHYS_ADDR, RSV_MAP_GIGAPAGE);
  rsv_sv39_pte_t* pte = &top_pt[idx];
  // Sanity check we got the right one.
  KASSERT(top_pt[idx - 1] == 0);
  KASSERT(top_pt[idx + 1] == 0);
  KASSERT(*pte & RSV_PTE_VALID);
  KASSERT((*pte >> 10) << 12 == RSV64_KERNEL_PHYS_ADDR);
  *pte = 0;
  rsv_sfence();
}

static void create_initial_meminfo(const dt_tree_t* fdt, memory_info_t* meminfo,
                                   phys_addr_t stack_base) {
  uint64_t mainmem_addr, mainmem_len;
  if (find_memory_node(fdt, &mainmem_addr, &mainmem_len) != 0) {
    die("Unable to find main memory information in FDT");
  }
  klogf("Found /memory node: <0x%lx - 0x%lx>\n", mainmem_addr,
        mainmem_addr + mainmem_len);

  meminfo->kernel_start_virt = (addr_t)&KERNEL_START_SYMBOL;
  meminfo->kernel_end_virt = (addr_t)&KERNEL_END_SYMBOL;

  // Some basic sanity checks.
  KASSERT(meminfo->kernel_start_virt >= RSV64_FIRST_KERNEL_ADDR);
  KASSERT(meminfo->kernel_start_virt >= RSV64_FIRST_USED_KERNEL_ADDR);
  KASSERT(meminfo->kernel_start_virt <= (addr_t)&create_initial_meminfo);
  KASSERT(meminfo->kernel_end_virt > meminfo->kernel_start_virt);
  KASSERT(meminfo->kernel_end_virt - meminfo->kernel_start_virt > 0x1000);
  KASSERT(meminfo->kernel_end_virt - meminfo->kernel_start_virt <
          RSV_MAP_GIGAPAGE_SIZE / 2);

  meminfo->kernel_start_phys =
      meminfo->kernel_start_virt - RSV64_KERNEL_VIRT_OFFSET;
  meminfo->kernel_end_phys =
      meminfo->kernel_end_virt - RSV64_KERNEL_VIRT_OFFSET;

  meminfo->mapped_start = RSV64_KERNEL_PHYS_ADDR + RSV64_KERNEL_VIRT_OFFSET;
  meminfo->mapped_end = meminfo->mapped_start + RSV_MAP_GIGAPAGE_SIZE;

  meminfo->phys_mainmem_begin = mainmem_addr;
  meminfo->lower_memory = 0;
  meminfo->upper_memory = mainmem_len;

  meminfo->phys_map_start = RSV64_KPHYSMAP_ADDR;
  meminfo->phys_map_length = RSV64_KPHYSMAP_LEN;
  meminfo->heap_start = RSV64_HEAP_START;
  meminfo->heap_end = RSV64_HEAP_START + RSV64_HEAP_LEN;

  // Point kernel_stack_base at the version of the stack in the kernel-mapped
  // space, not the physical map, to match the value of $sp.
  meminfo->kernel_stack_base = stack_base + RSV64_KERNEL_VIRT_OFFSET;
  meminfo->kernel_page_directory = rsv_get_hart_as();
}

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.
void kinit(int hart_id, phys_addr_t fdt_phys, phys_addr_t stack_base) {
  setup_kernel_mappings();

  klog("Booting APOS on riscv64\n");

  const void* fdt = (const void*)init_phys2virt(fdt_phys);
  if (dtfdt_print(fdt, true, &klog) != 0) {
    die("Bad FDT passed in");
  }

  dt_tree_t* fdt_tree = NULL;
  dtfdt_parse_result_t result =
      dt_create(fdt, &fdt_tree, &g_fdt_buf, INIT_FDT_BUFLEN);
  if (result != DTFDT_OK) {
    die("Unable to parse the FDT");
  }

  create_initial_meminfo(fdt_tree, &g_meminfo, stack_base);

  // We can't ever return or we'll page fault!
  while(1);
}
