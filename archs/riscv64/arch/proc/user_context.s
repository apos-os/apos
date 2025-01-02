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

.set SSTATUS_SPP,  0x100
.set SSTATUS_SIE,  0x002

.global user_context_apply

# void user_context_apply(const user_context_t* ctx);
user_context_apply:
  # TODO(aoates): figure out how to share this with interrupts_asm.s code.

  # Reset the interrupts level.
  mv s0, a0
  call kthread_reset_interrupt_level
  mv a0, s0

  # Return to user-mode.
  li t1, SSTATUS_SPP
  csrc sstatus, t1

  # ra and sp: we'll do later.
  ld gp,  0x010(a0)
  ld tp,  0x018(a0)
  ld t0,  0x020(a0)
  ld t1,  0x028(a0)
  ld t2,  0x030(a0)
  ld s0,  0x038(a0)
  ld s1,  0x040(a0)
  # do a0 later
  ld a1,  0x050(a0)
  ld a2,  0x058(a0)
  ld a3,  0x060(a0)
  ld a4,  0x068(a0)
  ld a5,  0x070(a0)
  ld a6,  0x078(a0)
  ld a7,  0x080(a0)
  ld s2,  0x088(a0)
  ld s3,  0x090(a0)
  ld s4,  0x098(a0)
  ld s5,  0x0a0(a0)
  ld s6,  0x0a8(a0)
  ld s7,  0x0b0(a0)
  ld s8,  0x0b8(a0)
  ld s9,  0x0c0(a0)
  ld s10, 0x0c8(a0)
  ld s11, 0x0d0(a0)
  ld t3,  0x0d8(a0)
  ld t4,  0x0e0(a0)
  ld t5,  0x0e8(a0)
  ld t6,  0x0f0(a0)

  # Block interrupts to avoid an interrupt in the next few instructions
  # clobbering sepc.
  li ra, SSTATUS_SIE
  csrc sstatus, ra

  # sepc = ctx->address
  ld ra, 0xf8(a0)
  csrw sepc, ra

  # Restore ra and sp, then a0.
  ld ra, 0(a0)
  ld sp, 0x08(a0)
  ld a0,  0x048(a0)

  sret
