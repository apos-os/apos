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

# Code to handle interrupts.

#.global int_handler
#int_handler:
#  iret

# Create an interrupt handler for the given exception (with error code).
.macro INT_ERROR intr
.global int\intr
int\intr :
  cli

  # The machine has pushed the first copy of the error number onto the stack,
  # currently at the top.

  pusha

  # Make a fake stack frame for GDB (original return address and EBP).
  mov 36(%esp), %eax  # get the original IP
  push %eax
  push %ebp
  mov %esp, %ebp

  # Copy the error code pushed for us onto the top of the stack as a function arg.
  mov 40(%esp), %eax
  push %eax
  push $\intr
  jmp int_common_handler
.endm

# Same as above, but for interrupt handlers that don't push an error code.  We
# first push a fake error code, then save all registers, then push the fake
# error code again, then the interrupt number.  This sets us up for
# int_common_handler in the same way as INT_ERROR (stack = error code, saved
# regs, error code, int number).
.macro INT_NOERROR intr
.global int\intr
int\intr :
  cli

  push $0  # fake error code
  pusha

  # Make a fake stack frame for GDB (original return address and EBP).
  mov 36(%esp), %eax  # get the original IP
  push %eax
  push %ebp
  mov %esp, %ebp

  push $0  # fake error code
  push $\intr
  jmp int_common_handler
.endm

INT_NOERROR   0
INT_NOERROR   1
INT_NOERROR   2
INT_NOERROR   3
INT_NOERROR   4
INT_NOERROR   5
INT_NOERROR   6
INT_NOERROR   7
INT_ERROR     8
INT_NOERROR   9
INT_ERROR     10
INT_ERROR     11
INT_ERROR     12
INT_ERROR     13
INT_ERROR     14
INT_NOERROR   15
INT_NOERROR   16
INT_ERROR     17
INT_NOERROR   18
INT_NOERROR   19

INT_NOERROR   32
INT_NOERROR   33
INT_NOERROR   34
INT_NOERROR   35
INT_NOERROR   36
INT_NOERROR   37
INT_NOERROR   38
INT_NOERROR   39
INT_NOERROR   40
INT_NOERROR   41
INT_NOERROR   42
INT_NOERROR   43
INT_NOERROR   44
INT_NOERROR   45
INT_NOERROR   46
INT_NOERROR   47

int_common_handler:
  # TODO(aoates): do segment switching, etc, once we have userland.
  call int_handler

  add $8, %esp  # pop interrupt and error numbers
  pop %ebp  # pop the fake GDB stack frame
  add $4, %esp

  popa
  add $4, %esp  # pop the other copy of the error number (the one pushed by the
                # processor, or the fake one we pushed to simulate it)
  sti
  iret
