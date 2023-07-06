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

#include "common/kassert.h"
#include "arch/dev/interrupts.h"
#include "proc/kthread-internal.h"

void kthread_arch_init(void) {
  die("unimplemented");
}

void kthread_arch_set_current_thread(kthread_t thread) {
  die("unimplemented");
}

void kthread_arch_init_thread(kthread_t thread,
                              kthread_trampoline_func_t trampoline,
                              kthread_start_func_t start_routine, void* arg) {
  die("unimplemented");
}

void kthread_arch_swap_context(kthread_t threadA, kthread_t threadB,
                               page_dir_ptr_t pdA, page_dir_ptr_t pdB) {
  die("unimplemented");
}
