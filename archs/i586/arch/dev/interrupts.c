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

#include "arch/dev/interrupts.h"
#include "arch/proc/user_context.h"
#include "archs/i586/internal/dev/faults.h"
#include "archs/i586/internal/dev/interrupts-x86.h"
#include "archs/i586/internal/memory/gdt.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/types.h"
#include "dev/interrupts.h"
#include "proc/defint.h"
#include "proc/kthread-internal.h"
#include "proc/user_prepare.h"

static uint16_t idt_entries = 0;
static idt_entry_t* idt = 0;

//extern void int_handler();
extern void int0(void);
extern void int1(void);
extern void int2(void);
extern void int3(void);
extern void int4(void);
extern void int5(void);
extern void int6(void);
extern void int7(void);
extern void int8(void);
extern void int9(void);
extern void int10(void);
extern void int11(void);
extern void int12(void);
extern void int13(void);
extern void int14(void);
extern void int15(void);
extern void int16(void);
extern void int17(void);
extern void int18(void);
extern void int19(void);

extern void int32(void);
extern void int33(void);
extern void int34(void);
extern void int35(void);
extern void int36(void);
extern void int37(void);
extern void int38(void);
extern void int39(void);
extern void int40(void);
extern void int41(void);
extern void int42(void);
extern void int43(void);
extern void int44(void);
extern void int45(void);
extern void int46(void);
extern void int47(void);

// User-defined handlers established by register_interrupt_handler().
static int_handler_t g_handlers[MAX_INTERRUPT + 1];

void register_interrupt_handler(uint8_t interrupt, int_handler_t handler) {
  KASSERT(interrupt <= MAX_INTERRUPT);
  g_handlers[interrupt] = handler;
}

// Register a RAW handler to be called when a particular interrupt fires.  The
// handler will be put in the IDT, and invoked directly when the interrupt
// fires.
typedef void (*raw_int_handler_t)(void);
static void register_raw_interrupt_handler(uint8_t num, raw_int_handler_t h) {
  KASSERT(idt != 0);
  KASSERT(num < idt_entries);

  _Static_assert(sizeof(h) == sizeof(uint32_t), "Invalid function ptr size");
  addr_t offset = (addr_t)h;
  idt[num].offset_low = offset & 0x0000FFFF;
  idt[num].offset_high = offset >> 16;
  idt[num].selector = IDT_SELECTOR_VALUE;
  idt[num].type_attr = 0 | IDT_PRESENT | IDT_DPL_RING0 | IDT_TYPE_32_INT;
}

static void register_task_gate(uint8_t num, int gate) {
  KASSERT(idt != 0);
  KASSERT(num < idt_entries);

  idt[num].offset_low = idt[num].offset_high = 0;
  idt[num].selector = segment_selector(gate, RPL_KERNEL);
  idt[num].type_attr = 0 | IDT_PRESENT | IDT_DPL_RING0 | IDT_TYPE_TASK_GATE;
}

// Given the ebp from int_common_handler (in isr.s), determine whether the
// interrupt occurred in user or kernel mode.
static int is_user_interrupt(addr_t ebp) {
  // The contents of the stack are,
  //  ebp+0x28 SS       (if a user interrupt)
  //  ebp+0x24 ESP      (if a user interrupt)
  //  ebp+0x20 EFLAGS
  //  ebp+0x1c CS
  //  ebp+0x18 Interrupted EIP
  //  ebp+0x14 Error code
  //  ebp+0x10 Interrupted EIP (again)
  //  ebp+0xc  Saved EBP
  //  ebp+0x8  Interrupt number
  //  ebp+0x4  Interrupt handler (pushed by 'call int_handler_common')
  //  ebp      Saved EBP          <-- *ebp
  //   <saved registers>
  const addr_t cs = *((addr_t*)ebp + 7);
  if (cs != segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER) &&
      cs != segment_selector(GDT_KERNEL_CODE_SEGMENT, RPL_KERNEL)) {
    klogf("unknown code segment: %#" PRIxADDR "\n", cs);
    die("unknown code segment");
  }
  const int is_user = (cs == segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER));

  // Do some sanity checking on the rest of the stack frame.
  if (ENABLE_KERNEL_SAFETY_NETS) {
    if (is_user) {
      const addr_t ss = *((addr_t*)ebp + 10);
      KASSERT(ss == segment_selector(GDT_USER_DATA_SEGMENT, RPL_USER));
    }
    KASSERT(*((addr_t*)ebp + 4) == *((addr_t*)ebp + 6));
    KASSERT(*((addr_t*)ebp + 2) < 256);
  }

  return is_user;
}

// Extract a user_context_t for the current interrupt, which must be a user-mode
// interrupt.
static user_context_t extract_interrupt_context(void* ebp_ptr) {
  const addr_t ebp = *(addr_t*)ebp_ptr;
  user_context_t context;

#if ENABLE_KERNEL_SAFETY_NETS
  const addr_t cs = *((addr_t*)ebp + 7);
  KASSERT_DBG(cs == segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER));
#endif

  context.type = USER_CONTEXT_INTERRUPT;
  context.esp = *((addr_t*)ebp + 9);
  context.ebp = *((addr_t*)*((addr_t*)ebp));
  context.eip = *((addr_t*)ebp + 6);
  context.eax = *((addr_t*)ebp - 1);
  context.ebx = *((addr_t*)ebp - 4);
  context.ecx = *((addr_t*)ebp - 2);
  context.edx = *((addr_t*)ebp - 3);
  context.esi = *((addr_t*)ebp - 7);
  context.edi = *((addr_t*)ebp - 8);

  context.eflags = *((addr_t*)ebp + 8);

  return context;
}

void interrupts_init(void) {
  // First, figure out where the IDT is.
  idt_ptr_t idt_ptr;
  asm volatile(
      "sidt (%1);"
      : "=m"(idt_ptr)
      : "r"((uint32_t)&idt_ptr) :);
  KASSERT(idt_ptr.limit % sizeof(idt_entry_t) == 0);
  idt_entries = idt_ptr.limit / sizeof(idt_entry_t);
  idt = (idt_entry_t*)idt_ptr.base;

  for (int i = 0; i < MAX_INTERRUPT; ++i) {
    g_handlers[i] = 0x0;
  }

  // TODO(aoates): Generate a handler for all interrupt vectors so that this
  // code doesn't have to know up front which will be needed.

  // Processor-generated interrupts.
  register_raw_interrupt_handler(0, &int0);
  register_raw_interrupt_handler(1, &int1);
  register_raw_interrupt_handler(2, &int2);
  register_raw_interrupt_handler(3, &int3);
  register_raw_interrupt_handler(4, &int4);
  register_raw_interrupt_handler(5, &int5);
  register_raw_interrupt_handler(6, &int6);
  register_raw_interrupt_handler(7, &int7);
  register_task_gate(8, GDT_TSS_DBLFAULT);
  register_raw_interrupt_handler(9, &int9);
  register_raw_interrupt_handler(10, &int10);
  register_raw_interrupt_handler(11, &int11);
  register_raw_interrupt_handler(12, &int12);
  register_raw_interrupt_handler(13, &int13);
  register_raw_interrupt_handler(14, &int14);
  register_raw_interrupt_handler(15, &int15);
  register_raw_interrupt_handler(16, &int16);
  register_raw_interrupt_handler(17, &int17);
  register_raw_interrupt_handler(18, &int18);
  register_raw_interrupt_handler(19, &int19);

  // IRQ interrupts.
  register_raw_interrupt_handler(0x20, &int32);
  register_raw_interrupt_handler(0x21, &int33);
  register_raw_interrupt_handler(0x22, &int34);
  register_raw_interrupt_handler(0x23, &int35);
  register_raw_interrupt_handler(0x24, &int36);
  register_raw_interrupt_handler(0x25, &int37);
  register_raw_interrupt_handler(0x26, &int38);
  register_raw_interrupt_handler(0x27, &int39);
  register_raw_interrupt_handler(0x28, &int40);
  register_raw_interrupt_handler(0x29, &int41);
  register_raw_interrupt_handler(0x2A, &int42);
  register_raw_interrupt_handler(0x2B, &int43);
  register_raw_interrupt_handler(0x2C, &int44);
  register_raw_interrupt_handler(0x2D, &int45);
  register_raw_interrupt_handler(0x2E, &int46);
  register_raw_interrupt_handler(0x2F, &int47);

  // Register common fault handlers.
  register_fault_handlers();
}

void int_handler(uint32_t interrupt, uint32_t error, addr_t ebp) {
  kthread_t thread = kthread_current_thread();
  if (thread) {
    int val = atomic_add_relaxed(&thread->interrupt_level, 1);
    KASSERT_DBG(val == 1 || val == 2);
  }

  const int is_user = is_user_interrupt(ebp);

  if (g_handlers[interrupt]) {
    g_handlers[interrupt](interrupt, error, is_user);
  } else {
    klogf("unhandled interrupt: 0x%x  error: 0x%x\n", interrupt, error);
  }

  defint_process_queued(/* force */ true);

  // Clobber some registers to cause loud failures if we don't restore them
  // properly.
  asm volatile (
      "movl $0, %%eax\n\t"
      "movl $0, %%ebx\n\t"
      "movl $0, %%ecx\n\t"
      "movl $0, %%edx\n\t"
      "movl $0, %%esi\n\t"
      "movl $0, %%edi\n\t"
      ::: "eax", "ebx", "ecx", "edx", "esi", "edi");

  if (is_user) {
    proc_prep_user_return(&extract_interrupt_context, &ebp, NULL);
  }

  if (thread) {
    KASSERT_DBG(atomic_load_relaxed(&thread->interrupt_level) >= 1);
    atomic_sub_relaxed(&thread->interrupt_level, 1);
  }

  // Note: we may never get here, if there were signals to dispatch.
}

void enable_interrupts(void) {
  asm volatile("sti");
}

void disable_interrupts(void) {
  asm volatile("cli");
}

// TODO(aoates): define these directly as asm.
interrupt_state_t get_interrupts_state(void) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(saved_flags));
  return saved_flags & IF_FLAG;
}

interrupt_state_t save_and_disable_interrupts(bool full_sync) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      "cli\n\t"
      : "=r"(saved_flags));
  _interrupt_noop_acquire();
  return saved_flags & IF_FLAG;
}

void restore_interrupts(interrupt_state_t saved, bool full_sync) {
  if (saved) {
    asm volatile ("sti");
  }
  _interrupt_noop_release();
}
