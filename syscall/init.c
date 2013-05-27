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

#include "memory/gdt.h"

long _syscall_enter(void);

void syscalls_init(void) {
  gdt_entry_t call_gate_entry =
      gdt_entry_create_gate((uint32_t)(&_syscall_enter),
                            GDT_KERNEL_CODE_SEGMENT << 3,
                            GATE_CALL,
                            3);
  gdt_install_segment(GDT_SYSCALL_CALL_GATE, call_gate_entry);
}
