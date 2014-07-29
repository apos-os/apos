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

#endif
