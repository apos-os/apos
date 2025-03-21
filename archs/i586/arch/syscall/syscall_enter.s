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
.global _syscall_enter

_syscall_enter:
  pushl %ebp  # arg6
  mov %esp, %ebp
  pushl %edi  # arg5
  pushl %esi  # arg4
  pushl %edx  # arg3
  pushl %ecx  # arg2
  pushl %ebx  # arg1
  pushl %eax  # syscall number
  call x86_syscall_dispatch
  add $28, %esp
  lret
