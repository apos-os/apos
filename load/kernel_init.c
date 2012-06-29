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

#include "load/gdt.h"
#include "load/mem_init.h"
#include "interrupts.h"
#include "memory.h"

extern void kmain(memory_info_t* meminfo);

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.  So it unmaps the first 4MB that were needed while paging
// was being initialized, and jumps to kmain.
void kinit(memory_info_t* meminfo) {
  // First, switch our stack to the virtual version (we're currently running on
  // an identity-mapped physical stack).
  __asm__ __volatile__(
      "movl %%esp, %%eax;"
      "add %0, %%eax;"
      "movl %%eax, %%esp;"
      "movl %%ebp, %%eax;"
      "add %0, %%eax;"
      "movl %%eax, %%ebp;"
      :: "i"(KERNEL_VIRT_START) : "eax");

  // Also switch our GDT and IDT pointers to their virtual addresses.
  gdt_ptr_t gdt_ptr;
  __asm__ __volatile__(
      "sgdt (%0);"
      :: "r"((uint32_t)&gdt_ptr) :);
  gdt_ptr.base += KERNEL_VIRT_START;
  gdt_flush(&gdt_ptr);

  idt_ptr_t idt_ptr;
  __asm__ __volatile__(
      "sidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);
  idt_ptr.base += KERNEL_VIRT_START;
  __asm__ __volatile__(
      "lidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);

  // setup_paging() in mem_init.c identity-maps the first PDE entry.  We want to
  // undo that.
  // The page directory is self-mapped at the end of the address space.
  uint32_t* page_directory = (uint32_t*)0xFFFFF000;
  page_directory[0] = 0 | PDE_WRITABLE;
  kmain(meminfo);

  // We can't ever return or we'll page fault!
  while(1);
}
