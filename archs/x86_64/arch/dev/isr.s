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

# Create an interrupt handler for the given exception (with error code).
.macro INT_ERROR intr
.global int\intr
int\intr :
  # The machine has pushed the first copy of the error number onto the stack,
  # currently at the top.
  push $0  # will be copy of interrupted EIP (see below)
  push %rbp
  mov %rsp, %rbp

  push $\intr
  call int_common_handler
.endm

# Same as above, but for interrupt handlers that don't push an error code.  We
# first push a fake error code, then continue as in INT_ERROR above.
.macro INT_NOERROR intr
.global int\intr
int\intr :
  push $0  # fake error code
  push $0  # will be copy of interrupted EIP (see below)
  push %rbp
  mov %rsp, %rbp

  push $\intr
  call int_common_handler
.endm

.global _int_handlers_start
_int_handlers_start:

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

.global _int_handlers_end
_int_handlers_end:

int_common_handler:
  push %rbp
  mov %rsp, %rbp

  # TODO(aoates): we don't really need all of these.
  push %rax
  push %rcx
  push %rdx
  push %rbx
  push %rsp
  push %rbp
  push %rsi
  push %rdi
  push %r8
  push %r9
  push %r10
  push %r11
  push %r12
  push %r13
  push %r14
  push %r15
  # TODO(aoates): save segment registers if coming from 32-bit segment.

  # Copy the interrupted EIP into our "stack frame" so that GDB gives useful
  # stack traces.  We can't do this before we pusha because we need to clobber a
  # register.
  mov 0x30(%rbp), %rax
  mov %rax, 0x20(%rbp)

  # Copy the interrupt number as a function arg.
  mov 0x10(%rbp), %rdi

  # Copy the error code pushed for us onto the top of the stack as a function arg.
  mov 0x28(%rbp), %rsi

  # Copy the %rbp as a funtion arg.
  mov %rbp, %rdx

  call int_handler

  # TODO(aoates): we don't really need all of these.
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %r11
  pop %r10
  pop %r9
  pop %r8
  pop %rdi
  pop %rsi
  pop %rbp
  pop %rsp
  pop %rbx
  pop %rdx
  pop %rcx
  pop %rax

  # Pop the fake stack frame EIP, the interrupt number, and the other copy of
  # the error number (the one pushed by the processor, or the fake one we pushed
  # to simulate it).
  add $0x18, %rsp
  pop %rbp
  add $0x10, %rsp

  iretq
