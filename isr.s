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

.global int_handler
int_handler:
  iret

# Create an IRQ handler for the given irq/interrupt pair.
.macro IRQ irq intr
.global irq\irq
irq\irq :
  cli
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
  add $8, %esp  # clean up pushed interrupt and IRQ numbers.
  sti
  iret
