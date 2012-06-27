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

#include "common/kassert.h"
#include "common/klog.h"
#include "interrupts.h"

static uint16_t idt_entries = 0;
static idt_entry_t* idt = 0;

void interrupts_init() {
  // First, figure out where the IDT is.
  idt_ptr_t idt_ptr;
  __asm __volatile__(
      "sidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);
  kassert(idt_ptr.limit % sizeof(idt_entry_t) == 0);
  idt_entries = idt_ptr.limit / sizeof(idt_entry_t);
  idt = (idt_entry_t*)phys2kernel(idt_ptr.base);
}
