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
.global i586_userret_callgate
.global i586_userret_interrupt

.set USER_SS, 0x23
.set USER_CS, 0x1b

i586_userret_callgate:
  push %ebp
  mov %esp, %ebp

  mov $USER_SS, %eax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %fs
  mov %ax, %gs
  pushl $USER_SS
  pushl 0x8(%ebp)  # context.esp
  pushl $USER_CS
  pushl 0xc(%ebp)  # context.eip
  mov 0x10(%ebp), %eax
  mov 0x14(%ebp), %ebx
  mov 0x18(%ebp), %ecx
  mov 0x1c(%ebp), %edx
  mov 0x20(%ebp), %esi
  mov 0x24(%ebp), %edi
  mov 0x28(%ebp), %ebp
  lret

i586_userret_interrupt:
  push %ebp
  mov %esp, %ebp

  mov $USER_SS, %eax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %fs
  mov %ax, %gs
  pushl $USER_SS
  pushl 0x8(%ebp)  # context.esp
  pushl 0x2c(%ebp)  # context.eflags
  pushl $USER_CS
  pushl 0xc(%ebp)  # context.eip
  mov 0x10(%ebp), %eax
  mov 0x14(%ebp), %ebx
  mov 0x18(%ebp), %ecx
  mov 0x1c(%ebp), %edx
  mov 0x20(%ebp), %esi
  mov 0x24(%ebp), %edi
  mov 0x28(%ebp), %ebp
  lret
