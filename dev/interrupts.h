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

// Code for registering and handling interrupts.
#ifndef APOO_INTERRUPTS_H
#define APOO_INTERRUPTS_H

#include <stdint.h>

void interrupts_init(void);

void enable_interrupts(void);
void disable_interrupts(void);

#define IF_FLAG 0x200

// Disable interrupts and return the previous (pre-disabling) IF flag value.
static inline uint32_t save_and_disable_interrupts(void);

// Restore interrupt state (given the return value of
// save_and_disable_interrupts).
static inline void restore_interrupts(uint32_t saved);

// Macros to use the functions above (and ensure they're called in pairs).
#define PUSH_AND_DISABLE_INTERRUPTS() \
    uint32_t _SAVED_INTERRUPTS = save_and_disable_interrupts()

#define POP_INTERRUPTS() \
    restore_interrupts(_SAVED_INTERRUPTS);

#define MIN_INTERRUPT 0
#define MAX_INTERRUPT 19

// Register a handler to be called when a particular interrupt fires.  The
// interrupt number must be between MIN_INTERRUPT and MAX_INTERRUPT.
//
// Use this to register normal handlers for things like page faults --- when the
// interrupt fires, a common stub will deal it, then invoke your handler with
// the interrupt number (and error, if applicable), then clean up after it
// returns.
typedef void (*int_handler_t)(
    uint32_t /* interrupt no. */, uint32_t /* error or 0 */);
void register_interrupt_handler(uint8_t interrupt, int_handler_t handler);

// Register a RAW handler to be called when a particular interrupt fires.  The
// handler will be put in the IDT, and invoked directly when the interrupt
// fires.
//
// This is probably not what you want --- use register_interrupt_handler above
// to set up a normal callback.  Only use this if you need custom stub code
// (like for IRQs).
typedef void (*raw_int_handler_t)(void);
void register_raw_interrupt_handler(uint8_t interrupt, raw_int_handler_t handler);

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

// Inline definitions.

static inline uint32_t save_and_disable_interrupts() {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      "cli\n\t"
      : "=r"(saved_flags));
  return saved_flags & IF_FLAG;
}

static inline void restore_interrupts(uint32_t saved) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(saved_flags));
  if (saved) {
    asm volatile ("sti");
  }
}

#endif
