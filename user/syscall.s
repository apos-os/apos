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

.global do_syscall

do_syscall:
  pushl %ebp
  movl %esp, %ebp

  pushl %ebx
  pushl %esi
  pushl %edi

  mov 8(%ebp), %eax  # syscall number
  mov 12(%ebp), %ebx # arg1
  mov 16(%ebp), %ecx # arg2
  mov 20(%ebp), %edx # arg3
  mov 24(%ebp), %esi # arg4
  mov 28(%ebp), %edi # arg5
  mov 32(%ebp), %ebp # arg6

  lcall  $0x33, $0

  popl %edi
  popl %esi
  popl %ebx
  popl %ebp
  ret
