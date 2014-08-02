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
  pushl %ebp
  movl %esp, %ebp

  # Push all the callee-registers
  pushl %ebx
  pushl %esi
  pushl %edi
  pushf

  # Store the current ESP in threadA.
  movl 8(%ebp), %eax
  movl %esp, KTHREAD_T_ESP(%eax)

  # Switch address spaces, if necessary.
  movl 20(%ebp), %ecx  # threadB->page_directory

  # if (threadA->page_directory != threadB->page_directory)
  cmp 16(%ebp), %ecx
  je no_cr3_switch_needed

  movl %ecx, %cr3

  no_cr3_switch_needed:

  # Load the ESP from threadB.
  movl 12(%ebp), %eax
  movl KTHREAD_T_ESP(%eax), %esp

  # Pop our state.
  popf
  popl %edi
  popl %esi
  popl %ebx
  popl %ebp
  ret
