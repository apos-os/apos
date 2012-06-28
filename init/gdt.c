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
#include "init/gdt.h"

#define GDT_NUM_ENTRIES 5
static gdt_entry_t g_gdt[GDT_NUM_ENTRIES] __attribute__((aligned (8)));

// Create a gdt_entry_t with the given parameters.
gdt_entry_t create_gdt_entry(uint32_t base, uint32_t limit, uint8_t type,
                             uint8_t dpl, uint8_t granularity) {
  gdt_entry_t entry;
  entry.base_low = base & 0x0000FFFF;
  entry.base_middle = (base >> 16) & 0x000000FF;
  entry.base_high = (base >> 24) & 0x000000FF;
  entry.limit_low = limit & 0x0000FFFF;
  entry.limit_high = (limit >> 16) & 0x0000000F;
  entry.type = type;
  entry.sys = 1;
  entry.dpl = dpl;
  entry.present = 1;
  entry.db = 1;  // Always set for 32 bit segments.
  entry.granularity = granularity;
  return entry;
}

void gdt_init() {
  // See section 3.4.5.1 of the Intel manuals for a description of the type
  // field.
  g_gdt[GDT_KERNEL_CODE_SEGMENT] =
      create_gdt_entry(0x0, 0x000FFFFF, 0xA, 0, 1);
  g_gdt[GDT_KERNEL_DATA_SEGMENT] =
      create_gdt_entry(0x0, 0x000FFFFF, 0x2, 0, 1);
  g_gdt[GDT_USER_CODE_SEGMENT] =
      create_gdt_entry(0x0, 0x000FFFFF, 0xA, 3, 1);
  g_gdt[GDT_USER_DATA_SEGMENT] =
      create_gdt_entry(0x0, 0x000FFFFF, 0x2, 3, 1);

  gdt_ptr_t gdtptr;
  gdtptr.base = (uint32_t)(&g_gdt);
  gdtptr.limit = GDT_NUM_ENTRIES * sizeof(gdt_entry_t) - 1;
  gdt_flush(&gdtptr);
}
