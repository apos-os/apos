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

#include "arch/proc/kthread.h"

#include <stddef.h>

#include "arch/dev/interrupts.h"
#include "archs/x86-common/internal/proc/kthread.h"
#include "archs/x86_64/internal/proc/tss.h"
#include "proc/kthread-internal.h"

// This asserts that the KTHREAD_T_ESP constant in kthread_asm.s matches the
// actual offset of the context member.
_Static_assert(offsetof(kthread_data_t, context) == 0x08,
               "KTHREAD_T_ESP doesn't match context offset");

void kthread_x64_trampoline(void);

void kthread_arch_init(void) {
  tss_init();
}

void kthread_arch_set_current_thread(kthread_t thread) {
  tss_set_kernel_stack(kthread_arch_kernel_stack_top(thread));
}

void kthread_arch_init_thread(kthread_t thread,
                              kthread_trampoline_func_t trampoline,
                              kthread_start_func_t start_routine, void* arg) {
  _Static_assert(sizeof(addr_t) == sizeof(uint64_t),
                 "Invalid addr_t for x64 code");

  addr_t* stack = (addr_t*)kthread_arch_kernel_stack_top(thread);

  // Set up the stack.
  *(stack--) = 0xDEADDEAD;
  // Jump into the trampoline at first.  Since args are passed in registers
  // rather than the stack in x64, we have a second level trampoline to pull
  // them out of memory before calling the generic trampoline.
  *(stack--) = (addr_t)(arg);
  *(stack--) = (addr_t)(start_routine);
  *(stack--) = (addr_t)(trampoline);
  *(stack--) = 0x0;  // Fake saved eip.
  *(stack--) = (addr_t)(kthread_x64_trampoline);

  // Set set up the stack as if we'd called swap_context().
  // First push the saved %ebp, which points to the ebp used by the 'call' to
  // swap_context -- since we jump into the trampoline (which will do it's own
  // thing with ebp), this doesn't have to be valid.
  *(stack--) = 0;  // rbp
  *(stack--) = 0;  // rbx
  *(stack--) = 0;  // r12
  *(stack--) = 0;  // r13
  *(stack--) = 0;  // r14
  *(stack--) = 0;  // r15

  // "push" the flags.
  uint64_t flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(flags));
  // Enable interrupts by default in the new thread.
  flags = flags | IF_FLAG;
  *(stack--) = flags;

  stack++;  // Point to last valid element.
  thread->context = (addr_t)stack;
}
