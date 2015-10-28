# Copyright 2014 Andrew Oates.  All Rights Reserved.
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

.set KTHREAD_T_ESP, 0x08

.global kthread_arch_swap_context
kthread_arch_swap_context:
  pushq %rbp
  movq %rsp, %rbp

  # Push all the callee-registers
  pushq %rbx
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  pushf

  # Store the current ESP in threadA.
  movq %rsp, KTHREAD_T_ESP(%rdi)

  # if (threadA->page_directory != threadB->page_directory)
  cmp %rdx, %rcx
  je no_cr3_switch_needed

  movq %rcx, %cr3

  no_cr3_switch_needed:

  # Load the ESP from threadB.
  movq KTHREAD_T_ESP(%rsi), %rsp

  # Pop our state.
  popf
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %rbx
  popq %rbp
  ret
