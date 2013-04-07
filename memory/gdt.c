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

#include <stdint.h>
#include "memory/gdt.h"

gdt_entry_t MULTILINK(gdt_entry_create) (
    uint32_t base, uint32_t limit, uint8_t type,
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

void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr) {
  asm("    movl %0, %%eax\n"
      "    lgdt (%%eax)\n"
      ""
      "    # Load the ring-0 segments into the segment registers.\n"
      "    mov $0x10, %%ax\n"
      "    mov %%ax, %%ds\n"
      "    mov %%ax, %%es\n"
      "    mov %%ax, %%fs\n"
      "    mov %%ax, %%gs\n"
      "    mov %%ax, %%ss\n"
      "    ljmp $0x08, $.flush\n"
      ".flush:\n" :: "g"(gdt_ptr) : "eax");
}
