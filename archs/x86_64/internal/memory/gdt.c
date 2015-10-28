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

#include "archs/x86_64/internal/memory/gdt.h"
#include "archs/x86_64/internal/proc/tss.h"
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
   unsigned int :1;              // Unused.
   unsigned int l:1;             // 64-bit flag.
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
   uint32_t offset_high2;
   uint8_t reserved;
   uint8_t zero3;
   uint16_t reserved2;
} __attribute__((packed)) gdt_gate_entry_t;
_Static_assert(sizeof(gdt_gate_entry_t) == 2 * sizeof(gdt_entry_t),
               "gdt_gate_entry_t incorrect size");

gdt_entry_t MULTILINK(gdt_entry_create_segment) (
    uint32_t base, uint32_t limit, gdt_seg_type_t type,
    uint8_t flags, uint8_t dpl, uint8_t granularity, bool is64bit) {
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
  }

  switch (type) {
    case SEG_CODE:
      entry->l = is64bit;
      entry->sys = 1;
      entry->db = is64bit ? 0 : 1;
      break;

    case SEG_DATA:
      entry->sys = 1;
      entry->db = 1;
      break;
  }

  entry->dpl = dpl;
  entry->present = 1;
  entry->granularity = granularity;
  return entry_data;
}

void MULTILINK(gdt_entry_create_tss) (addr_t base, gdt_entry_t entry[2]) {
  gdt_segment_entry_t* entry_lower = (gdt_segment_entry_t*)(&entry[0]);
  entry_lower->base_low = base & 0x0000FFFF;
  entry_lower->base_middle = (base >> 16) & 0x000000FF;
  entry_lower->base_high = (base >> 24) & 0x000000FF;
  entry_lower->limit_low = (sizeof(tss_t) - 1) & 0x0000FFFF;
  entry_lower->limit_high = ((sizeof(tss_t) - 1) >> 16) & 0x0000000F;
  entry_lower->type = 0x9;

  entry_lower->l = 0;
  entry_lower->sys = 0;
  entry_lower->db = 0;
  entry_lower->dpl = 0;
  entry_lower->present = 1;
  entry_lower->granularity = 0;

  entry[1].data[0] = base >> 32;
  entry[1].data[1] = 0;
}

int MULTILINK(gdt_entry_create_gate) (
    addr_t offset, uint16_t seg_selector, gdt_gate_type_t type, uint8_t dpl,
    gdt_entry_t* out) {
  gdt_gate_entry_t* entry = (gdt_gate_entry_t*)out;
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

  out[1].data[0] = offset >> 32;
  out[1].data[1] = 0;
  return 2;
}

void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr) {
  KASSERT_DBG(segment_selector(GDT_KERNEL_CODE_SEGMENT, RPL_KERNEL) == 0x08);
  KASSERT_DBG(segment_selector(GDT_KERNEL_DATA_SEGMENT, RPL_KERNEL) == 0x10);
  asm("    movq %0, %%rax\n"
      "    lgdt (%%rax)\n"
      ""
      "    # Load the ring-0 segments into the segment registers.\n"
      "    mov $0x10, %%ax\n"
      "    mov %%ax, %%ds\n"
      "    mov %%ax, %%es\n"
      "    mov %%ax, %%fs\n"
      "    mov %%ax, %%gs\n"
      "    mov %%ax, %%ss\n"
      ""
      "    pushq $0x08\n"
      "    pushq $gdt_flush%=\n"
      "    lretq\n"
      "gdt_flush%=:\n" :: "g"(gdt_ptr) : "rax");
}

void MULTILINK(gdt_install_segment) (int index, gdt_entry_t entry) {
  gdt_ptr_t gdt_ptr;
  asm volatile (
      "sgdt (%0);"
      :: "r"((uint64_t)&gdt_ptr) :);

  KASSERT(index > 0 && index < GDT_NUM_ENTRIES);
  gdt_entry_t* entries = (gdt_entry_t*)gdt_ptr.base;
  entries[index] = entry;
  MULTILINK(gdt_flush) (&gdt_ptr);
}
