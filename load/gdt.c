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

// Code to initialize the GDT.

#include <stdint.h>

#include "common/types.h"
#include "memory/gdt.h"

static gdt_entry_t g_gdt[GDT_NUM_ENTRIES] __attribute__((aligned (8)));

void gdt_init() {
  // See section 3.4.5.1 of the Intel manuals for a description of the type
  // field.
  g_gdt[GDT_KERNEL_CODE_SEGMENT] =
      gdt_entry_create_PHYS(0x0, 0x000FFFFF, SEG_CODE, 0x2, 0, 1);
  g_gdt[GDT_KERNEL_DATA_SEGMENT] =
      gdt_entry_create_PHYS(0x0, 0x000FFFFF, SEG_DATA, 0x2, 0, 1);
  g_gdt[GDT_USER_CODE_SEGMENT] =
      gdt_entry_create_PHYS(0x0, 0x000FFFFF, SEG_CODE, 0x2, 3, 1);
  g_gdt[GDT_USER_DATA_SEGMENT] =
      gdt_entry_create_PHYS(0x0, 0x000FFFFF, SEG_DATA, 0x2, 3, 1);

  gdt_ptr_t gdtptr;
  gdtptr.base = (uint32_t)(&g_gdt);
  gdtptr.limit = GDT_NUM_ENTRIES * sizeof(gdt_entry_t) - 1;
  gdt_flush_PHYS(&gdtptr);
}
