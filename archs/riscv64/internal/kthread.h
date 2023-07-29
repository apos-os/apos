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

#ifndef APOO_ARCHS_RISCV64_INTERNAL_KTHREAD_H
#define APOO_ARCHS_RISCV64_INTERNAL_KTHREAD_H

#include "archs/riscv64/internal/memlayout.m4.h"
#include "common/types.h"
#include "proc/kthread-internal.h"

// Return the bottom of the current thread's kernel stack.  This is the address
// ONE STACK SLOT ABOVE the first element on the stack, if anything has been
// pushed.
static inline addr_t kthread_arch_kernel_stack_bottom(kthread_t thread) {
  return (addr_t)thread->stack + thread->stacklen - sizeof(addr_t) +
         RSV64_KSTACK_SCRATCH_NBYTES;
}

#endif
