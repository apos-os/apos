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

#include "archs/i586/internal/memory/gdt.h"
#include "common/kassert.h"

typedef struct {
   uint16_t limit_low;           // Lower 16 bits of the limit.
   uint16_t base_low;            // Lower 16 bits of the base.
   uint8_t  base_middle;         // Middle 8 bits of the base.
   unsigned int type:4;          // Type of segment.
   unsigned int sys:1;           // System or regular descriptor.
   unsigned int dpl:2;           // Descriptor protection level (ring).
   unsigned int present:1;
   unsigned int limit_high:4;    // Upper 4 bits of the limit.
   unsigned int :2;              // Unused.
   unsigned int db:1;            // Default/bound flag.
   unsigned int granularity:1;   // Limit granularity (0 = bytes, 1 = 4kbs)
   uint8_t  base_high;           // Last 8 bits of the base.
} __attribute__((packed)) gdt_segment_entry_t;
_Static_assert(sizeof(gdt_segment_entry_t) == sizeof(gdt_entry_t),
               "gdt_segment_entry_t incorrect size");

typedef struct {
   uint16_t offset_low;          // Lower 16 bits of the offset.
   uint16_t segment;             // Segment selector.
   uint8_t  zero1;               // <must be zero>
   unsigned int type:4;          // Type of segment.
   unsigned int zero2:1;         // <must be zero>
   unsigned int dpl:2;           // Descriptor protection level (ring).
   unsigned int present:1;
   uint16_t offset_high;         // Upper 16 bits of the offset.
} __attribute__((packed)) gdt_gate_entry_t;
_Static_assert(sizeof(gdt_gate_entry_t) == sizeof(gdt_entry_t),
               "gdt_gate_entry_t incorrect size");

gdt_entry_t MULTILINK(gdt_entry_create_segment) (
    uint32_t base, uint32_t limit, gdt_seg_type_t type,
    uint8_t flags, uint8_t dpl, uint8_t granularity) {
  gdt_entry_t entry_data;
  gdt_segment_entry_t* entry = (gdt_segment_entry_t*)(&entry_data);
  entry->base_low = base & 0x0000FFFF;
  entry->base_middle = (base >> 16) & 0x000000FF;
  entry->base_high = (base >> 24) & 0x000000FF;
  entry->limit_low = limit & 0x0000FFFF;
  entry->limit_high = (limit >> 16) & 0x0000000F;

  switch (type) {
    case SEG_CODE: entry->type = 0x8 | flags; break;
    case SEG_DATA: entry->type = flags; break;
    case SEG_TSS: entry->type = 0x9; break;
  }

  switch (type) {
    case SEG_CODE:
    case SEG_DATA:
      entry->sys = 1;
      entry->db = 1;  // Always set for 32 bit segments.
      break;

    case SEG_TSS:
      entry->sys = 0;
      entry->db = 0;
      break;
  }

  entry->dpl = dpl;
  entry->present = 1;
  entry->granularity = granularity;
  return entry_data;
}

gdt_entry_t MULTILINK(gdt_entry_create_gate) (
    uint32_t offset, uint16_t seg_selector, gdt_gate_type_t type, uint8_t dpl) {
  gdt_entry_t entry_data;
  gdt_gate_entry_t* entry = (gdt_gate_entry_t*)(&entry_data);
  entry->offset_low = offset & 0xFFFF;
  entry->offset_high = (offset >> 16) & 0xFFFF;
  entry->segment = seg_selector;
  entry->zero1 = 0;
  switch (type) {
    case GATE_CALL: entry->type = 0xC;
  }
  entry->zero2 = 0;
  entry->dpl = dpl;
  entry->present = 1;
  return entry_data;
}

void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr) {
  asm("    movl %0, %%eax\n"
      "    lgdt (%%eax)\n"
      "    mov $0, %%ax\n"
      "    lldt %%ax\n"
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

void MULTILINK(gdt_install_segment) (int index, gdt_entry_t entry) {
  gdt_ptr_t gdt_ptr;
  asm volatile (
      "sgdt (%0);"
      :: "r"((uint32_t)&gdt_ptr) :);

  KASSERT(index > 0 && index < GDT_NUM_ENTRIES);
  gdt_entry_t* entries = (gdt_entry_t*)gdt_ptr.base;
  entries[index] = entry;
  MULTILINK(gdt_flush) (&gdt_ptr);
}
