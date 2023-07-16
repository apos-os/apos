// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "archs/riscv64/internal/kthread.h"
#include "common/kassert.h"
#include "proc/kthread-internal.h"

void riscv_kthread_trampoline(void);

void kthread_arch_init(void) {}

void kthread_arch_set_current_thread(kthread_t thread) {
  // TODO(riscv): set kernel-mode stack for stack switching.
}

void kthread_arch_init_thread(kthread_t thread,
                              kthread_trampoline_func_t trampoline,
                              kthread_start_func_t start_routine, void* arg) {
  addr_t* stack = (addr_t*)kthread_arch_kernel_stack_top(thread);

  // Set up the stack.  Pass the args to the riscv trampoline in s1-s3.
  *(stack--) = 0xDEADDEAD;
  *(stack--) = (addr_t)&riscv_kthread_trampoline;
  *(stack--) = 0;  // fp
  *(stack--) = 0xDEADDEAD;  // unused
  *(stack--) = 0;  // s11
  *(stack--) = 0;  // s10
  *(stack--) = 0;  // s9
  *(stack--) = 0;  // s8
  *(stack--) = 0;  // s7
  *(stack--) = 0;  // s6
  *(stack--) = 0;  // s5
  *(stack--) = 0;  // s4
  *(stack--) = (addr_t)arg;  // s3
  *(stack--) = (addr_t)start_routine;  // s2
  *(stack--) = (addr_t)trampoline;  // s1

  thread->context = (addr_t)stack;
}
