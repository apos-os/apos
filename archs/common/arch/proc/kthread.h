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

#ifndef APOO_ARCHS_COMMON_ARCH_PROC_KTHREAD_H
#define APOO_ARCHS_COMMON_ARCH_PROC_KTHREAD_H

#include "proc/kthread.h"
#include "memory/memory.h"

typedef void* (*kthread_start_func_t)(void*);
typedef void (*kthread_trampoline_func_t)(kthread_start_func_t start,
                                          void* arg);

// Initialize any necessary data structures.  Called once at boot (from
// kthread_init).
void kthread_arch_init(void);

// Mark the given thread as current in whatever ways necessary for the
// architecture.
void kthread_arch_set_current_thread(kthread_t thread);

// Initialze the given thread's context.  It should be set to a state as if it
// had been switched out in kthread_arch_swap_context().  When switched into in
// a subsequent kthread_arch_swap_context() call, it should,
//  - enable interrupts
//  - restore any other flag state to the state when this was called
//  - run the given trampoline function, passing 'start' and 'arg' as arguments
void kthread_arch_init_thread(kthread_t thread,
                              kthread_trampoline_func_t trampoline,
                              kthread_start_func_t start_routine, void* arg);

// Swap context from threadA (the currently running thread) to threadB (the new
// thread).
//
// Defined in kthread_asm.s
void kthread_arch_swap_context(kthread_t threadA, kthread_t threadB,
                               page_dir_ptr_t pdA, page_dir_ptr_t pdB);

#endif
