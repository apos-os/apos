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

#include "common/kassert.h"
#include "common/klog.h"
#include "interrupts.h"

static uint16_t idt_entries = 0;
static idt_entry_t* idt = 0;

extern void int_handler();
extern void irq0();
extern void irq1();
extern void irq2();
extern void irq3();
extern void irq4();
extern void irq5();
extern void irq6();
extern void irq7();
extern void irq8();
extern void irq9();
extern void irq10();
extern void irq11();
extern void irq12();
extern void irq13();
extern void irq14();
extern void irq15();

void register_interrupt_handler(uint8_t num, int_handler_t h) {
  kassert(idt != 0);
  kassert(num < idt_entries);

  uint32_t offset = (uint32_t)h;
  idt[num].offset_low = offset & 0x0000FFFF;
  idt[num].offset_high = offset >> 16;
  idt[num].selector = IDT_SELECTOR_VALUE;
  idt[num].type_attr = 0 | IDT_PRESENT | IDT_DPL_RING0 | IDT_TYPE_32_INT;
}

void interrupts_init() {
  // First, figure out where the IDT is.
  idt_ptr_t idt_ptr;
  __asm__ __volatile__(
      "sidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);
  kassert(idt_ptr.limit % sizeof(idt_entry_t) == 0);
  idt_entries = idt_ptr.limit / sizeof(idt_entry_t);
  idt = (idt_entry_t*)idt_ptr.base;

  // Install a test keyboard handler.
  for (int i = 0; i < idt_entries; ++i) {
    register_interrupt_handler(i, &int_handler);
  }
  register_interrupt_handler(0x20, &irq0);
  register_interrupt_handler(0x21, &irq1);
  register_interrupt_handler(0x22, &irq2);
  register_interrupt_handler(0x23, &irq3);
  register_interrupt_handler(0x24, &irq4);
  register_interrupt_handler(0x25, &irq5);
  register_interrupt_handler(0x26, &irq6);
  register_interrupt_handler(0x27, &irq7);
  register_interrupt_handler(0x28, &irq8);
  register_interrupt_handler(0x29, &irq9);
  register_interrupt_handler(0x2A, &irq10);
  register_interrupt_handler(0x2B, &irq11);
  register_interrupt_handler(0x2C, &irq12);
  register_interrupt_handler(0x2D, &irq13);
  register_interrupt_handler(0x2E, &irq14);
  register_interrupt_handler(0x2F, &irq15);

  // Enable interrupts.
  __asm__ __volatile__("sti");
}
