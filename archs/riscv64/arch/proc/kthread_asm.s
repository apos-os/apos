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

.set KTHREAD_T_SP, 0x08

.global riscv_kthread_trampoline
riscv_kthread_trampoline:
  call enable_interrupts_raw
  mv a0, s2  # start_routine
  mv a1, s3  # arg
  jr s1

.global kthread_arch_swap_context
# void kthread_arch_swap_context(kthread_t threadA, kthread_t threadB,
#                                page_dir_ptr_t pdA, page_dir_ptr_t pdB);
kthread_arch_swap_context:
  addi sp, sp, -112
  sd ra, 104(sp)
  sd fp, 96(sp)
  addi fp, sp, 112  # Keep in sync with stack_trace.c

  # Save all the callee-registers
  # did ra
  # did fp/s0
  sd s1,  0x00(sp)
  sd s2,  0x08(sp)
  sd s3,  0x10(sp)
  sd s4,  0x18(sp)
  sd s5,  0x20(sp)
  sd s6,  0x28(sp)
  sd s7,  0x30(sp)
  sd s8,  0x38(sp)
  sd s9,  0x40(sp)
  sd s10, 0x48(sp)
  sd s11, 0x50(sp)
  # No need to save interrupt state --- interrupts should always be disabled
  # KASSERT(sstatus & SIE == 0)

  # Store the current SP in threadA.
  sd sp, KTHREAD_T_SP(a0)

  # if (threadA->page_directory != threadB->page_directory)
  beq a2, a3, .Lskip_satp_switch
  csrw satp, a3
  sfence.vma

.Lskip_satp_switch:
  # Load the SP from threadB.
  ld sp, KTHREAD_T_SP(a1)

  # Pop our state.
  ld s1,  0x00(sp)
  ld s2,  0x08(sp)
  ld s3,  0x10(sp)
  ld s4,  0x18(sp)
  ld s5,  0x20(sp)
  ld s6,  0x28(sp)
  ld s7,  0x30(sp)
  ld s8,  0x38(sp)
  ld s9,  0x40(sp)
  ld s10, 0x48(sp)
  ld s11, 0x50(sp)

  ld ra, 104(sp)
  ld fp, 96(sp)
  addi sp, sp, 112
  ret
