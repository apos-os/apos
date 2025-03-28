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

.global sigreturn_trampoline32_start
.global sigreturn_trampoline32_end

sigreturn_trampoline32_start:
.code32
  mov $21, %eax  # SYS_SIGRETURN
  mov 12(%esp), %ebx  # address of old signal mask (arg1)
  mov 8(%esp), %ecx   # address of user context (arg2)
  mov 4(%esp), %edx   # address of syscall context (arg3)
  lcall  $0x33, $0
  hlt  # Should never get here.
sigreturn_trampoline32_end:
