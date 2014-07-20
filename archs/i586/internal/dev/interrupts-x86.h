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

// X86-specific definitions and declarations (i.e., any code that uses these is
// architecture-specific by definition).
#ifndef APOO_ARCHS_I586_ARCH_DEV_INTERRUPTS_X86_H
#define APOO_ARCHS_I586_ARCH_DEV_INTERRUPTS_X86_H

#include <stdint.h>

#define MIN_INTERRUPT 0
#define MAX_INTERRUPT 0x2f

// Register a handler to be called when a particular interrupt fires.  The
// interrupt number must be between MIN_INTERRUPT and MAX_INTERRUPT.
//
// Use this to register normal handlers for things like page faults --- when the
// interrupt fires, a common stub will deal it, then invoke your handler with
// the interrupt number (and error, if applicable), then clean up after it
// returns.
typedef void (*int_handler_t)(
    uint32_t /* interrupt no. */, uint32_t /* error or 0 */, int /* is_user */);
void register_interrupt_handler(uint8_t interrupt, int_handler_t handler);

// Structs for the IDT and its entries.
typedef struct {
   uint16_t offset_low;
   uint16_t selector;
   uint8_t zero;
   uint8_t type_attr;
   uint16_t offset_high;
} __attribute__((packed)) idt_entry_t;

typedef struct {
   uint16_t limit;
   uint32_t base;
} __attribute__((packed)) idt_ptr_t;

#define IDT_PRESENT 0x80
#define IDT_DPL_RING0 0x00
#define IDT_DPL_RING3 0x60
#define IDT_TYPE_32_INT 0x0E

// The kernel's code segment selector.  Make sure this matches the one set in
// gdt_flush.s.
#define IDT_SELECTOR_VALUE 0x08

#endif
