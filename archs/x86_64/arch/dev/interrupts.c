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

#include "arch/proc/user_context.h"
#include "archs/x86_64/internal/dev/faults.h"
#include "archs/x86_64/internal/dev/interrupts-x86.h"
#include "archs/x86_64/internal/memory/gdt.h"
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

static void dblfault_handler(uint32_t interrupt, uint32_t error, bool is_user) {
  die("Kernel double fault");
}

void register_interrupt_handler(uint8_t interrupt, int_handler_t handler) {
  KASSERT(interrupt <= MAX_INTERRUPT);
  g_handlers[interrupt] = handler;
}

// Register a RAW handler to be called when a particular interrupt fires.  The
// handler will be put in the IDT, and invoked directly when the interrupt
// fires.
typedef void (*raw_int_handler_t)(void);
static void register_raw_interrupt_handler(uint8_t num, int ist,
                                           raw_int_handler_t h) {
  KASSERT(idt != 0);
  KASSERT(num < idt_entries);
  KASSERT(ist >= 0);
  KASSERT(ist <= 7);

  //_Static_assert(sizeof(h) == sizeof(uint32_t), "Invalid function ptr size");
  addr_t offset = (addr_t)h;
  idt[num].offset_low = offset & 0x0000FFFF;
  idt[num].offset_high = (offset >> 16) & 0xFFFF;
  idt[num].offset_high2 = offset >> 32;
  idt[num].selector = IDT_SELECTOR_VALUE;
  idt[num].type_attr = IDT_PRESENT | IDT_DPL_RING0 | IDT_TYPE_64_INT;
  idt[num].ist = ist;
  idt[num].reserved = 0;
}

// Given the rbp from int_common_handler (in isr.s), determine whether the
// interrupt occurred in user or kernel mode.
static int is_user_interrupt(addr_t rbp) {
  // The contents of the stack are,
  //  rbp+0x50 SS       (if a user interrupt)
  //  rbp+0x48 RSP      (if a user interrupt)
  //  rbp+0x40 RFLAGS
  //  rbp+0x38 CS
  //  rbp+0x30 Interrupted RIP
  //  rbp+0x28 Error code
  //  rbp+0x20 Interrupted RIP (again)
  //  rbp+0x18 Saved RBP
  //  rbp+0x10 Interrupt number
  //  rbp+0x8  Interrupt handler (pushed by 'call int_handler_common')
  //  rbp      Saved RBP          <-- *rbp
  //   <saved registers>
  const addr_t cs = *((addr_t*)rbp + 7);
  if (cs != segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER) &&
      cs != segment_selector(GDT_KERNEL_CODE_SEGMENT, RPL_KERNEL)) {
    klogf("unknown code segment: 0x%lx\n", cs);
    die("unknown code segment");
  }
  const int is_user =
      (cs == segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER));

  // Do some sanity checking on the rest of the stack frame.
  if (ENABLE_KERNEL_SAFETY_NETS) {
      const addr_t ss = *((addr_t*)rbp + 10);
    if (is_user) {
      KASSERT(ss == segment_selector(GDT_USER_DATA_SEGMENT_32, RPL_USER));
    } else {
      // On a 32-to-64-bit transition via a call gate, the ss will be set to 0.
      KASSERT(ss == segment_selector(GDT_KERNEL_DATA_SEGMENT, RPL_KERNEL) ||
              ss == 0x0);
    }
    KASSERT(*((addr_t*)rbp + 4) == *((addr_t*)rbp + 6));
    KASSERT(*((addr_t*)rbp + 2) < 256);
  }

  return is_user;
}

// Extract a user_context_t for the current interrupt, which must be a user-mode
// interrupt.
static user_context_t extract_interrupt_context(void* rbp_ptr) {
  const addr_t rbp = *(addr_t*)rbp_ptr;
  user_context_t context;

#if ENABLE_KERNEL_SAFETY_NETS
  const addr_t cs = *((addr_t*)rbp + 7);
  KASSERT_DBG(cs == segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER));
#endif

  context.type = USER_CONTEXT_INTERRUPT;
  context.is64 = false;
  context.rsp = *((addr_t*)rbp + 9);
  context.rbp = *((addr_t*)*((addr_t*)rbp));
  context.rip = *((addr_t*)rbp + 6);
  context.rax = *((addr_t*)rbp - 1);
  context.rbx = *((addr_t*)rbp - 4);
  context.rcx = *((addr_t*)rbp - 2);
  context.rdx = *((addr_t*)rbp - 3);
  context.rsi = *((addr_t*)rbp - 7);
  context.rdi = *((addr_t*)rbp - 8);
  context.r8 = *((addr_t*)rbp - 9);
  context.r9 = *((addr_t*)rbp - 10);
  context.r10 = *((addr_t*)rbp - 11);
  context.r11 = *((addr_t*)rbp - 12);
  context.r12 = *((addr_t*)rbp - 13);
  context.r13 = *((addr_t*)rbp - 14);
  context.r14 = *((addr_t*)rbp - 15);
  context.r15 = *((addr_t*)rbp - 16);

  context.rflags = *((addr_t*)rbp + 8);

  return context;
}

void interrupts_init(void) {
  // First, figure out where the IDT is.
  idt_ptr_t idt_ptr;
  asm volatile(
      "sidt (%1);"
      : "=m"(idt_ptr)
      : "r"((addr_t)&idt_ptr) :);
  KASSERT(idt_ptr.limit % sizeof(idt_entry_t) == 0);
  idt_entries = idt_ptr.limit / sizeof(idt_entry_t);
  idt = (idt_entry_t*)idt_ptr.base;

  for (int i = 0; i < MAX_INTERRUPT; ++i) {
    g_handlers[i] = 0x0;
  }

  // TODO(aoates): Generate a handler for all interrupt vectors so that this
  // code doesn't have to know up front which will be needed.

  // Processor-generated interrupts.
  // TODO(aoates): consider using a dedicated stack for all interrupts, not just
  // the double-fault.
  register_raw_interrupt_handler(0, 0, &int0);
  register_raw_interrupt_handler(1, 0, &int1);
  register_raw_interrupt_handler(2, 0, &int2);
  register_raw_interrupt_handler(3, 0, &int3);
  register_raw_interrupt_handler(4, 0, &int4);
  register_raw_interrupt_handler(5, 0, &int5);
  register_raw_interrupt_handler(6, 0, &int6);
  register_raw_interrupt_handler(7, 0, &int7);
  register_raw_interrupt_handler(8, 1, &int8);
  register_raw_interrupt_handler(9, 0, &int9);
  register_raw_interrupt_handler(10, 0, &int10);
  register_raw_interrupt_handler(11, 0, &int11);
  register_raw_interrupt_handler(12, 0, &int12);
  register_raw_interrupt_handler(13, 0, &int13);
  register_raw_interrupt_handler(14, 0, &int14);
  register_raw_interrupt_handler(15, 0, &int15);
  register_raw_interrupt_handler(16, 0, &int16);
  register_raw_interrupt_handler(17, 0, &int17);
  register_raw_interrupt_handler(18, 0, &int18);
  register_raw_interrupt_handler(19, 0, &int19);

  // IRQ interrupts.
  register_raw_interrupt_handler(0x20, 0, &int32);
  register_raw_interrupt_handler(0x21, 0, &int33);
  register_raw_interrupt_handler(0x22, 0, &int34);
  register_raw_interrupt_handler(0x23, 0, &int35);
  register_raw_interrupt_handler(0x24, 0, &int36);
  register_raw_interrupt_handler(0x25, 0, &int37);
  register_raw_interrupt_handler(0x26, 0, &int38);
  register_raw_interrupt_handler(0x27, 0, &int39);
  register_raw_interrupt_handler(0x28, 0, &int40);
  register_raw_interrupt_handler(0x29, 0, &int41);
  register_raw_interrupt_handler(0x2A, 0, &int42);
  register_raw_interrupt_handler(0x2B, 0, &int43);
  register_raw_interrupt_handler(0x2C, 0, &int44);
  register_raw_interrupt_handler(0x2D, 0, &int45);
  register_raw_interrupt_handler(0x2E, 0, &int46);
  register_raw_interrupt_handler(0x2F, 0, &int47);

  // We bounce this through int8 so the stack is set up in the same way as other
  // interrupts.
  register_interrupt_handler(8, &dblfault_handler);

  // Register common fault handlers.
  register_fault_handlers();
}

void int_handler(uint32_t interrupt, uint32_t error, addr_t rbp) {
  kthread_t thread = kthread_current_thread();
  if (thread) {
    int val = atomic_add_relaxed(&thread->interrupt_level, 1);
    KASSERT_DBG(val == 1 || val == 2);
  }
  const int is_user = is_user_interrupt(rbp);

  if (g_handlers[interrupt]) {
    g_handlers[interrupt](interrupt, error, is_user);
  } else {
    klogf("unhandled interrupt: 0x%x  error: 0x%x\n", interrupt, error);
  }

  defint_process_queued(/* force */ true);

  // Clobber some registers to cause loud failures if we don't restore them
  // properly.
  if (ENABLE_KERNEL_SAFETY_NETS) {
    asm volatile (
        "movq $0, %%rax\n\t"
        "movq $0, %%rbx\n\t"
        "movq $0, %%rcx\n\t"
        "movq $0, %%rdx\n\t"
        "movq $0, %%rsi\n\t"
        "movq $0, %%rdi\n\t"
        "movq $0, %%r8\n\t"
        "movq $0, %%r9\n\t"
        "movq $0, %%r10\n\t"
        "movq $0, %%r11\n\t"
        ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
            "r8", "r9", "r10", "r11");
  }

  if (is_user) {
    proc_prep_user_return(&extract_interrupt_context, &rbp, NULL);
  }

  // Note: we may never get here, if there were signals to dispatch.

  if (thread) {
    KASSERT_DBG(atomic_load_relaxed(&thread->interrupt_level) >= 1);
    atomic_sub_relaxed(&thread->interrupt_level, 1);
  }
}

void enable_interrupts(void) {
  asm volatile("sti");
}

void disable_interrupts(void) {
  asm volatile("cli");
}

// TODO(aoates): define these directly as asm.
interrupt_state_t get_interrupts_state(void) {
  uint64_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(saved_flags));
  return (saved_flags & IF_FLAG) != 0;
}

interrupt_state_t save_and_disable_interrupts(bool full_sync) {
  uint64_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      "cli\n\t"
      : "=r"(saved_flags));
  _interrupt_noop_acquire();
  return (saved_flags & IF_FLAG) != 0;
}

void restore_interrupts(interrupt_state_t saved, bool full_sync) {
  if (saved) {
    asm volatile ("sti");
  }
  _interrupt_noop_release();
}
