# Copyright 2023 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.include "archs/riscv64/internal/memlayout.m4.s"

.global _kstart                         # making entry point visible to linker

# Virtual offset for the kernel mapping.  Keep in sync with the linker script
# and memory setup code.
.set RSV64_KERNEL_VIRT_ADDR, RSV64_KERNEL_PHYS_ADDR + RSV64_KERNEL_VIRT_OFFSET

# reserve initial kernel stack space
.set STACKSIZE, 0x8000                  # that is, 32k.
.lcomm initial_kstack, STACKSIZE        # reserve stack on a doubleword boundary

# Initial page table structure.
.local initial_page_table
.comm initial_page_table, 0x1000, 0x1000

.type _kstart, @function
_kstart:
  # TODO(riscv): we need to set gp to __global_pointer$.  Figure out how to
  # get GP relaxations working, then set that up.

  # Set up basic paging (SV39).  Map the gigapage containing the kernel into its
  # physical (identity) and virtual addresses.  We will create mappings for
  # 0x8000000 - 0xbfffffff (1GB) physical, and that plus KERNEL_VIRT_OFFSET.

  # Ensure paging is disabled to start.
  csrw satp, zero

  # Create an entry for the kernel image (all sections).  Assume it is no more
  # than 1GB is size.  Then link that entry twice, once at the kernel code's
  # physical address, and once at the virtual address.
  # TODO(aoates): separate data and text for the kernel (here and other archs).
  # TODO(aoates): assert somehow that the kernel is contained in this range.
  li t0, RSV64_KERNEL_PHYS_ADDR
  srli t0, t0, 12   # Get the PPN
  slli t0, t0, 10   # Move it to bit 10 in the PTE
  ori t0, t0, 0x2f  # Global bit, RWX + V

  # Calculate which page table entry for phys and virt ranges.
  la t2, initial_page_table
  li t3, 0x7FFFFFFFFF  # SV39 address mask.
  li t1, RSV64_KERNEL_PHYS_ADDR
  and t1, t1, t3   # Mask for SV39
  srli t1, t1, 30  # idx = t1 >> 30 (For SV39 gigapages, shift 30 bits)
  slli t1, t1, 3   # offset = t1 << 3 (table offset = idx * sizeof(entry))
  add t1, t1, t2   # addr = &initial_page_table + offset
  sd t0, (t1)

  li t1, RSV64_KERNEL_VIRT_ADDR
  and t1, t1, t3   # Mask for SV39
  srli t1, t1, 30  # idx = t1 >> 30 (For SV39 gigapages, shift 30 bits)
  slli t1, t1, 3   # offset = t1 << 3 (table offset = idx * sizeof(entry))
  add t1, t1, t2   # addr = &initial_page_table + offset
  sd t0, (t1)

  # Install the page table.
  li t0, 8  # MODE = SV39
  slli t0, t0, 60
  la t1, initial_page_table
  srli t1, t1, 12  # Get the PNN of the initial_page_table.
  or t0, t0, t1  # SATP = mode | PPN (ASID is zero)

  csrw satp, t0
  sfence.vma

  # Set up stack.  Go straight to the virtual address.
  la t0, initial_kstack
  li t1, RSV64_KERNEL_VIRT_OFFSET
  add t0, t0, t1
  li t1, STACKSIZE
  add sp, t0, t1

  # We need to manually load the address because the code model doesn't allow
  # jumping more than +/- 2GB with default relocations.
  # kinit(hart_id /* from SBI */, FDTptr /* from SBI */, stack_base)
  la a2, initial_kstack
  la t0, kinit
  jr t0
