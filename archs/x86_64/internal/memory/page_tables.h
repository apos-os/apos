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

#ifndef APOO_ARCHS_I586_INTERNAL_MEMORY_PAGE_TABLES_H
#define APOO_ARCHS_I586_INTERNAL_MEMORY_PAGE_TABLES_H

#include "arch/memory/layout.h"

#define VIRT_ADDR_MASK 0x0000FFFFFFFFFFFF

#define PML4E_NX              0x8000000000000000
#define PML4E_ADDRESS_MASK    0x7FFFFFFFFFFFF000
#define PML4E_ACCESSED        0x0000000000000020
#define PML4E_CACHE_DISABLED  0x0000000000000010
#define PML4E_WRITE_THROUGH   0x0000000000000008
#define PML4E_USER_ACCESS     0x0000000000000004
#define PML4E_WRITABLE        0x0000000000000002
#define PML4E_PRESENT         0x0000000000000001
#define PML4_NUM_ENTRIES     (PAGE_SIZE / 8)

#define PDPTE_NX             0x8000000000000000
#define PDPTE_ADDRESS_MASK   0x7FFFFFFFFFFFF000  // PAGE_INDEX_MASK
#define PDPTE_PAT            0x0000000000001000  // Only if PS is set (1GB page)
#define PDPTE_GLOBAL         0x0000000000000100  // Only if PS is set (1GB page)
#define PDPTE_LARGE_PAGES    0x0000000000000080
#define PDPTE_DIRTY          0x0000000000000040  // Only if PS is set (1GB page)
#define PDPTE_ACCESSED       0x0000000000000020
#define PDPTE_CACHE_DISABLED 0x0000000000000010
#define PDPTE_WRITE_THROUGH  0x0000000000000008
#define PDPTE_USER_ACCESS    0x0000000000000004
#define PDPTE_WRITABLE       0x0000000000000002
#define PDPTE_PRESENT        0x0000000000000001
#define PDPT_NUM_ENTRIES    (PAGE_SIZE / 8)

#define PDE_NX             0x8000000000000000
#define PDE_ADDRESS_MASK   0x7FFFFFFFFFFFF000  // PAGE_INDEX_MASK
#define PDE_PAT            0x0000000000001000  // Only if PS is set (2MB page)
#define PDE_GLOBAL         0x0000000000000100  // Only if PS is set (2MB page)
#define PDE_LARGE_PAGES    0x0000000000000080
#define PDE_DIRTY          0x0000000000000040  // Only if PS is set (2MB page)
#define PDE_ACCESSED       0x0000000000000020
#define PDE_CACHE_DISABLED 0x0000000000000010
#define PDE_WRITE_THROUGH  0x0000000000000008
#define PDE_USER_ACCESS    0x0000000000000004
#define PDE_WRITABLE       0x0000000000000002
#define PDE_PRESENT        0x0000000000000001
#define PD_NUM_ENTRIES    (PAGE_SIZE / 8)

#define PTE_NX             0x8000000000000000
#define PTE_ADDRESS_MASK   0x7FFFFFFFFFFFF000  // PAGE_INDEX_MASK
#define PTE_GLOBAL         0x0000000000000100
#define PTE_PAT            0x0000000000000080
#define PTE_DIRTY          0x0000000000000040
#define PTE_ACCESSED       0x0000000000000020
#define PTE_CACHE_DISABLED 0x0000000000000010
#define PTE_WRITE_THROUGH  0x0000000000000008
#define PTE_USER_ACCESS    0x0000000000000004
#define PTE_WRITABLE       0x0000000000000002
#define PTE_PRESENT        0x0000000000000001
#define PT_NUM_ENTRIES    (PAGE_SIZE / 8)

#endif
