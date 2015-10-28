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

# Kernel entrance point for syscalls from userland.
.global _syscall_enter32

_syscall_enter32:
  # TODO(aoates): do this masking in a more elegant/general way when generalized
  # 32/64-bit conversions for syscalls are implemented.
  movq $0xffffffff, %r8
  andq %r8, %rbp  # arg6
  andq %r8, %rdi  # arg5
  andq %r8, %rsi  # arg4
  andq %r8, %rdx  # arg3
  andq %r8, %rcx  # arg2
  andq %r8, %rbx  # arg1
  andq %r8, %rax  # syscall number

  # TODO(aoates): shuffle the args around without lazily using the stack.
  pushq %rbp  # arg6
  mov %rsp, %rbp
  pushq %rdi  # arg5
  pushq %rsi  # arg4
  pushq %rdx  # arg3
  pushq %rcx  # arg2
  pushq %rbx  # arg1
  pushq %rax  # syscall number

  # x86-64 calling conventions.
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %r8
  popq %r9
  call syscall_dispatch
  add $8, %rsp
  lretq
