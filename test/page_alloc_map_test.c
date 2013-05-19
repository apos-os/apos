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
#include "dev/interrupts.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/page_fault.h"
#include "test/ktest.h"

// Expectations for page faults we want to see.
static uint32_t expected_address = 0;
static uint32_t expected_error = 0;
static uint32_t expected_orig_return_address = 0;
static uint32_t expected_new_return_address = 0;
static int expected_seen = 0;

// Expect a page fault for the given address/error.  When it occurs, the handler
// will search the stack for the original return_address, then change that to
// the new return_address, which should be the next instruction AFTER the one
// expected to cause the fault.
void expect_page_fault(uint32_t address, uint32_t error,
                       uint32_t orig_return_address,
                       uint32_t new_return_address) {
  expected_address = address;
  expected_error = error;
  expected_seen = 0;
  expected_orig_return_address = orig_return_address;
  expected_new_return_address = new_return_address;
}

// Interrupt handler just for the tests.  It allows us to expect page faults
// and catch them for tests.
void test_page_fault_handler(uint32_t interrupt, uint32_t error) {
  KASSERT(interrupt == 0x0E);

  uint32_t address;
  asm volatile ("movl %%cr2, %0\n\t" : "=r"(address));

  if (expected_seen) {
    KEXPECT_EQ(0, expected_seen);
  } else {
    KEXPECT_EQ(address, expected_address);
    KEXPECT_EQ(error, expected_error);
    expected_seen = 1;
  }

  // Walk up the stack and change where we're returning.  This is pretty kooky.
  uint32_t* esp;
  int limit = 512;
  asm volatile ("movl %%esp, %0\n\t" : "=g"(esp));
  // We have to do it twice --- once for the fake stack frame generated in isr.s
  // for GDB's sake, and once for the actual return address.
  for (int i = 0; i < 2; ++i) {
    // Look for an address on the stack thats in between the orig and new return
    // addresses.
    while (*esp <= expected_orig_return_address ||
           *esp >= expected_new_return_address) {
      if (limit-- == 0) {
        die("couldn't find return address in test_page_fault_handler");
      }
      esp++;
    }
    *esp = expected_new_return_address;
  }
  // I can't believe I just wrote that code...
}

// Test page mapping.  Note: will cause page faults and crash the kernel!
void page_alloc_map_test() {
  KTEST_SUITE_BEGIN("page_alloc map/unmap test");
  // Set up test handler.
  register_interrupt_handler(0x0E, &test_page_fault_handler);

  // Chosen to be in the middle of a page table for maximal testyness.
  uint8_t* addr = (uint8_t*)0x80047014;

  // Should page fault:
  KTEST_BEGIN("page fault");
  expect_page_fault((uint32_t)addr, 0x02, (uint32_t)&&fault_A, (uint32_t)&&recover_A);
fault_A:
  *addr = 10;
recover_A:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);

  // Set up mapping.
  KTEST_BEGIN("valid mapping");
  uint32_t phys_page = page_frame_alloc();
  page_frame_map_virtual((uint32_t)addr & PDE_ADDRESS_MASK, phys_page,
                         MEM_PROT_ALL, MEM_ACCESS_KERNEL_ONLY, 0);

  // Should succeed:
  *addr = 10;

  // Should be able to touch anything in that page.
  uint8_t* addr2 = 0;
  for (uint32_t i = 0; i < 4096; ++i) {
    addr2 = (uint8_t*)(((uint32_t)addr & PDE_ADDRESS_MASK) + i);
    *addr2 = 10;
  }

  // ...but not anything before or after.
  uint8_t* addr_before = (uint8_t*)(((uint32_t)addr & PDE_ADDRESS_MASK) - 1);
  expect_page_fault((uint32_t)addr_before, 0x02,
                    (uint32_t)&&fault_B, (uint32_t)&&recover_B);
fault_B:
  *addr_before = 10;
recover_B:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);

  uint8_t* addr_after = (uint8_t*)(
      ((uint32_t)addr & PDE_ADDRESS_MASK) + PAGE_SIZE);
  expect_page_fault((uint32_t)addr_after, 0x02,
                    (uint32_t)&&fault_C, (uint32_t)&&recover_C);
fault_C:
  *addr_after = 10;
recover_C:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);


  // Make a mapping for a different page in the same table.  Shouldn't require
  // creating a new table (step in to verify).
  KTEST_BEGIN("new mapping in same table");
  addr2 = addr - 2 * 4096;
  page_frame_map_virtual((uint32_t)addr2 & PDE_ADDRESS_MASK, phys_page,
                         MEM_PROT_ALL, MEM_ACCESS_KERNEL_ONLY, 0);

  // Both should succeed (and affect each other, since they're mapped to the
  // same page):
  *addr = 15;
  KEXPECT_EQ(15, *addr2);
  *addr2 = 20;
  KEXPECT_EQ(20, *addr);
  KEXPECT_EQ(20, *addr2);

  // REMAPPING.
  // Remap addr to a NEW physical page, without unmapping in between.
  KTEST_BEGIN("remapping");
  uint32_t phys_page2 = page_frame_alloc();
  page_frame_map_virtual((uint32_t)addr & PDE_ADDRESS_MASK, phys_page2,
                         MEM_PROT_ALL, MEM_ACCESS_KERNEL_ONLY, 0);

  *addr = 71;
  *addr2 = 72;
  KEXPECT_EQ(71, *addr);
  KEXPECT_EQ(72, *addr2);

  // Unmap the original mapping.
  KTEST_BEGIN("unmapping");
  page_frame_unmap_virtual((uint32_t)addr & PDE_ADDRESS_MASK);

  // Should still succeed:
  *addr2 = 30;
  KEXPECT_EQ(30, *addr2);

  // Should page fault:
  expect_page_fault((uint32_t)addr, 0x02, (uint32_t)&&fault_D, (uint32_t)&&recover_D);
fault_D:
  *addr = 25;
recover_D:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);

  KTEST_BEGIN("unmapping range");
  // First set up a multi-page mapping.
  page_frame_map_virtual((uint32_t)addr & PDE_ADDRESS_MASK, phys_page,
                         MEM_PROT_ALL, MEM_ACCESS_KERNEL_ONLY, 0);
  page_frame_map_virtual(((uint32_t)addr & PDE_ADDRESS_MASK) + PAGE_SIZE,
                         phys_page,
                         MEM_PROT_ALL, MEM_ACCESS_KERNEL_ONLY, 0);

  *addr = 25;
  *(uint32_t*)((uint32_t)addr + PAGE_SIZE) = 25;

  // ...then unmap both.
  page_frame_unmap_virtual_range((uint32_t)addr & PDE_ADDRESS_MASK,
                                 2 * PAGE_SIZE);

  // Accesses to both pages should page fault.
  expect_page_fault((uint32_t)addr, 0x02, (uint32_t)&&fault_E, (uint32_t)&&recover_E);
fault_E:
  *addr = 25;
recover_E:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);

  expect_page_fault((uint32_t)addr + PAGE_SIZE, 0x02, (uint32_t)&&fault_F, (uint32_t)&&recover_F);
fault_F:
  *(uint32_t*)((uint32_t)addr + PAGE_SIZE) = 25;
recover_F:
  addr = addr;
  KEXPECT_EQ(1, expected_seen);

  // Restore original handler.
  // TODO(aoates): get the actual original handler to restore instead of
  // hardcoding this.
  register_interrupt_handler(0x0E, &page_fault_handler);
}

// TODO(aoates): test protections, access flags, etc.
