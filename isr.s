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
  pusha
  # Copy the error code pushed for us onto the top of the stack as a function arg.
  mov 32(%esp), %eax
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

int_common_handler:
  # TODO(aoates): do segment switching, etc, once we have userland.
  call int_handler

  # DEBUG
  # Clobber %eax, %ebx, %edx (caller-save) to fail loudly if we
  # aren't saving them properly.
  mov $0xAAAAAAAA, %eax
  mov $0xBBBBBBBB, %ebx
  mov $0xDDDDDDDD, %edx

  add $8, %esp  # pop interrupt and error numbers
  popa
  add $4, %esp  # pop the other copy of the error number
  sti
  iret


# Create an IRQ handler for the given irq/interrupt pair.
.macro IRQ irq intr
.global irq\irq
irq\irq :
  cli
  pusha
  push $\intr
  push $\irq 
  jmp irq_common_handler
.endm

IRQ 0,  0x20
IRQ 1,  0x21
IRQ 2,  0x22
IRQ 3,  0x23
IRQ 4,  0x24
IRQ 5,  0x25
IRQ 6,  0x26
IRQ 7,  0x27
IRQ 8,  0x28
IRQ 9,  0x29
IRQ 10, 0x2A
IRQ 11, 0x2B
IRQ 12, 0x2C
IRQ 13, 0x2D
IRQ 14, 0x2E
IRQ 15, 0x2F

irq_common_handler:
  # TODO(aoates): do segment switching, etc, once we have userland.
  call irq_handler

  # DEBUG
  # Clobber %eax, %ebx, %edx (caller-save) to fail loudly if we
  # aren't saving them properly.
  mov $0xAAAAAAAA, %eax
  mov $0xBBBBBBBB, %ebx
  mov $0xDDDDDDDD, %edx

  add $8, %esp  # clean up pushed interrupt and IRQ numbers.
  popa
  sti
  iret
