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

.set SSTATUS_SIE, 0x2
.set SSTATUS_SPP, 0x100

# void enable_interrupts(void)
.global enable_interrupts
enable_interrupts:
  csrsi sstatus, SSTATUS_SIE
  ret

# void disable_interrupts(void)
.global disable_interrupts
disable_interrupts:
  csrci sstatus, SSTATUS_SIE
  ret

# interrupt_state_t get_interrupts_state(void)
.global get_interrupts_state
get_interrupts_state:
  csrr a0, sstatus
  andi a0, a0, SSTATUS_SIE
  ret

# interrupt_state_t save_and_disable_interrupts(void)
.global save_and_disable_interrupts
save_and_disable_interrupts:
  # Read sstatus and clear SIE
  csrrci a0, sstatus, SSTATUS_SIE
  andi a0, a0, SSTATUS_SIE
  ret

# void restore_interrupts(interrupt_state_t saved)
.global restore_interrupts
restore_interrupts:
  beqz a0, .done
  csrsi sstatus, SSTATUS_SIE
.done:
  ret

.global _int_handlers_start
.global _int_handlers_end
_int_handlers_start:

.global int_handler_asm
int_handler_asm:
  # TODO(riscv): handle SPIE properly.
  # TODO(riscv): switch stacks when coming from user mode
  # TODO(riscv): do we need to save sepc/scause/etc?  What if we get a nested
  # trap?  Currently those registers are the only s-mode visible registers that
  # are _not_ fully restored here, which is fine for most S code.
  addi sp, sp, -256
  sd ra,  0x0000(sp)
  sd sp,  0x0008(sp)
  sd gp,  0x0010(sp)
  sd tp,  0x0018(sp)
  sd t0,  0x0020(sp)
  sd t1,  0x0028(sp)
  sd t2,  0x0030(sp)
  sd s0,  0x0038(sp)
  sd s1,  0x0040(sp)
  sd a0,  0x0048(sp)
  sd a1,  0x0050(sp)
  sd a2,  0x0058(sp)
  sd a3,  0x0060(sp)
  sd a4,  0x0068(sp)
  sd a5,  0x0070(sp)
  sd a6,  0x0078(sp)
  sd a7,  0x0080(sp)
  sd s2,  0x0088(sp)
  sd s3,  0x0090(sp)
  sd s4,  0x0098(sp)
  sd s5,  0x00a0(sp)
  sd s6,  0x00a8(sp)
  sd s8,  0x00b0(sp)
  sd s9,  0x00b8(sp)
  sd s10, 0x00c0(sp)
  sd s11, 0x00c8(sp)
  sd t3,  0x00d0(sp)
  sd t4,  0x00d8(sp)
  sd t5,  0x00e0(sp)
  sd t6,  0x00e8(sp)

  csrr a0, scause
  csrr a1, stval
  csrr a2, sepc
  csrr a3, sstatus
  andi a3, a3, SSTATUS_SPP

  call int_handler

  ld ra,  0x0000(sp)
  ld sp,  0x0008(sp)
  ld gp,  0x0010(sp)
  ld tp,  0x0018(sp)
  ld t0,  0x0020(sp)
  ld t1,  0x0028(sp)
  ld t2,  0x0030(sp)
  ld s0,  0x0038(sp)
  ld s1,  0x0040(sp)
  ld a0,  0x0048(sp)
  ld a1,  0x0050(sp)
  ld a2,  0x0058(sp)
  ld a3,  0x0060(sp)
  ld a4,  0x0068(sp)
  ld a5,  0x0070(sp)
  ld a6,  0x0078(sp)
  ld a7,  0x0080(sp)
  ld s2,  0x0088(sp)
  ld s3,  0x0090(sp)
  ld s4,  0x0098(sp)
  ld s5,  0x00a0(sp)
  ld s6,  0x00a8(sp)
  ld s8,  0x00b0(sp)
  ld s9,  0x00b8(sp)
  ld s10, 0x00c0(sp)
  ld s11, 0x00c8(sp)
  ld t3,  0x00d0(sp)
  ld t4,  0x00d8(sp)
  ld t5,  0x00e0(sp)
  ld t6,  0x00e8(sp)
  addi sp, sp, 256
  sret

_int_handlers_end:
