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

basic_user_test:
  li a0, 100  # SYS_SYSCALL_TEST
  li a1, 1
  li a2, 2
  li a3, 3
  li a4, 4
  li a5, 5
  li a6, 6
  li a7, 7  # Shouldn't be used
  ecall

  mv a1, a0  # Call exit() with result.
  li a0, 14  # exit()
  ecall

segfault_test:
  li a0, 0x123
  jr a0

sigaction_test:
  # Assume a0 has the address of the handler and sp is a valid stack.
  addi sp, sp, -16  # sizeof(ksigaction_t)
  sd a0, 0(sp)      # action->handler = a0
  sw zero, 8(sp)    # action->sa_mask = 0
  sw zero, 12(sp)   # action->sa_flags = 0

  # Jankily assume that the handler-plus-1000 is our shared buffer, since we
  # can't link this code.
  addi s1, a0, 1000
  li t1, 123
  sd t1, (s1)

  # sigaction(SIGUSR1, ctx, NULL)
  li a0, 20  # SYS_SIGACTION
  li a1, 19  # SIGUSR1
  mv a2, sp
  mv a3, zero
  ecall

  # my_pid = getpid()
  li a0, 16  # SYS_GETPID
  ecall

  # sigkill(my_pid, SIGUSR1)
  mv a1, a0
  li a0, 19  # SYS_KILL
  li a2, 19  # SIGUSR1
  ecall

  # The handler should have run (and modified the buffer).
  # exit(*buf)
  li a0, 14  # SYS_EXIT
  ld a1, (s1)
  ecall

sigaction_test_handler:
  auipc s1, 0   # get buffer address
  addi s1, s1, 1000
  addi sp, sp, -16
  li t1, 0xDEADDEADDEADDEAD
  sd t1, 0(sp)
  sd t1, 8(sp)

  # Call another syscall, for good measure.
  li a0, 100  # SYS_SYSCALL_TEST
  li a1, 2
  li a2, 3
  li a3, 4
  li a4, 5
  li a5, 6
  li a6, 7
  ecall

  sd a0, (s1)
  addi sp, sp, 16
  ret
