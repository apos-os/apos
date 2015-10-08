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

# The actual code that jumps into userspace.
.global x86_64_userret_callgate
.global x86_64_userret_interrupt

.set USER_SS_32, 0x23
.set USER_CS_32, 0x1b

x86_64_userret_callgate:
  pushq %rbp
  mov %rsp, %rbp

  mov $USER_SS_32, %rax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %fs
  mov %ax, %gs
  pushq $USER_SS_32
  pushq (%rdi)  # context.rsp
  pushq $USER_CS_32
  pushq 0x10(%rdi)  # context.rip
  mov 0x08(%rdi), %rbp
  mov 0x18(%rdi), %rax
  mov 0x20(%rdi), %rbx
  mov 0x28(%rdi), %rcx
  mov 0x30(%rdi), %rdx
  mov 0x38(%rdi), %rsi
  mov 0x48(%rdi), %r8
  mov 0x50(%rdi), %r9
  mov 0x58(%rdi), %r10
  mov 0x60(%rdi), %r11
  mov 0x68(%rdi), %r12
  mov 0x70(%rdi), %r13
  mov 0x78(%rdi), %r14
  mov 0x80(%rdi), %r15
  mov 0x40(%rdi), %rdi
  lretq

x86_64_userret_interrupt:
  pushq %rbp
  mov %rsp, %rbp

  mov $USER_SS_32, %rax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %fs
  mov %ax, %gs
  pushq $USER_SS_32
  pushq (%rdi)  # context.rsp
  pushq 0x88(%rdi)  # context.rflags
  pushq $USER_CS_32
  pushq 0x10(%rdi)  # context.rip
  mov 0x08(%rdi), %rbp
  mov 0x18(%rdi), %rax
  mov 0x20(%rdi), %rbx
  mov 0x28(%rdi), %rcx
  mov 0x30(%rdi), %rdx
  mov 0x38(%rdi), %rsi
  mov 0x48(%rdi), %r8
  mov 0x50(%rdi), %r9
  mov 0x58(%rdi), %r10
  mov 0x60(%rdi), %r11
  mov 0x68(%rdi), %r12
  mov 0x70(%rdi), %r13
  mov 0x78(%rdi), %r14
  mov 0x80(%rdi), %r15
  mov 0x40(%rdi), %rdi

  iretq
