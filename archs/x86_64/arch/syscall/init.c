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

#include "arch/syscall/init.h"
#include "archs/x86_64/internal/memory/gdt.h"
#include "common/kassert.h"
#include "common/types.h"

long _syscall_enter32(void);

void syscalls_init(void) {
  gdt_entry_t call_gate_entries[2];
  KASSERT(2 == gdt_entry_create_gate(
                   (addr_t)(&_syscall_enter32),
                   segment_selector(GDT_KERNEL_CODE_SEGMENT, RPL_KERNEL),
                   GATE_CALL, 3, call_gate_entries));
  gdt_install_segment(GDT_SYSCALL_CALL_GATE, call_gate_entries[0]);
  gdt_install_segment(GDT_SYSCALL_CALL_GATE_UPPER, call_gate_entries[1]);
}
