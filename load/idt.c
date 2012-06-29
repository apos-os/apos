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

// Code to initialize the IDT.  Very similar to the code it gdt.c.

#include <stdint.h>

#include "dev/interrupts.h"

// TODO(aoates): we don't really need all these entries (we don't use all the
// interrupts).
#define NUM_IDT_ENTRIES 256
static idt_entry_t idt_entries[NUM_IDT_ENTRIES];
static idt_ptr_t   idt_ptr;

extern void idt_flush(uint32_t gdt);

void idt_init() {
  idt_ptr.limit = sizeof(idt_entry_t) * NUM_IDT_ENTRIES;
  idt_ptr.base  = (uint32_t)&idt_entries;

  for (int i = 0; i < NUM_IDT_ENTRIES; ++i) {
    idt_entries[i].offset_low = 0;
    idt_entries[i].selector = IDT_SELECTOR_VALUE;
    idt_entries[i].zero = 0;
    idt_entries[i].type_attr = IDT_DPL_RING0 | IDT_TYPE_32_INT;
    idt_entries[i].offset_high = 0;
  }

  __asm__ __volatile__(
      "lidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);
}
