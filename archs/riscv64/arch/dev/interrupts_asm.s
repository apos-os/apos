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

.include "archs/riscv64/internal/memlayout.m4.s"

.set SSTATUS_SIE,  0x002
.set SSTATUS_SPIE, 0x020
.set SSTATUS_SPP,  0x100
.set SSTATUS_SAVE_MASK, SSTATUS_SPIE | SSTATUS_SPP

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

# In int_handler_asm we create a sorta fake stack frame to help with unwinding.
# It's not perfect --- GDB still gets confused, and when a leaf function is
# interrupted it is unable to unwind past the leaf function (since ra isn't
# saved on the stack).
.global int_handler_asm
int_handler_asm:
  # sscratch holds the address of a guaranteed scratch spot at the bottom of the
  # current thread's kernel-mode stack.  Swap out s1 to get that address, then
  # save s2 to it to get a free register.
  csrrw s1, sscratch, s1

  # Save s2 and sp to our scratch spots, then decide if we need to switch stacks
  sd s2, 0(s1)
  sd sp, -8(s1)

  csrr s2, sstatus
  andi s2, s2, SSTATUS_SPP
  # If interrupted kernel mode, use our stack as-is.
  # TODO(aoates): catch double-faults for stack overflows.
  bnez s2, .Lstack_done

  # We interrupted user mode and need to switch stacks.  sscratch is the bottom
  # (highest address) of the kernel stack, so start right after that.
  mv sp, s1  # Original sp saved above.
  addi sp, sp, RSV64_KSTACK_SCRATCH_NBYTES

.Lstack_done:
  ld s2, -8(s1)
  sd s2, -24(sp)         # Save original sp onto new stack.
  ld s2, 0(s1)            # Get saved s2 from the scratch spot.
  csrrw s1, sscratch, s1  # Restore s1 and sscratch.
  # Now everything is as it was, except we may have switched stacks.

  # TODO(riscv): do we need to save sepc/scause/etc?  What if we get a nested
  # trap (for example, a page fault on the stack while pushing context)?
  # Currently those registers are the only s-mode visible registers that are
  # _not_ fully restored here, which is fine for most S code.
  addi sp, sp, -272
  # Save the original ra value as a local variable.  We need to restore it
  # later, but if the code we interrupted is a leaf function, this ra likely
  # points to _its_ caller, so if we use it for our stack frame it will look
  # like we skipped the function that was actually called.
  sd ra, 0(sp)
  # Now pretend as if the interrupted code called us.
  csrr ra, sepc
  # Now create the start of our standard stack frame.
  sd ra, 264(sp)
  sd fp, 256(sp)
  addi fp, sp, 272  # fake frame

  # Now save all our other registers.
  # ra: is already stored at 0(sp)
  # sp: no need to store sp again
  sd gp,  0x0010(sp)
  sd tp,  0x0018(sp)
  sd t0,  0x0020(sp)
  sd t1,  0x0028(sp)
  sd t2,  0x0030(sp)
  # Skip s0/fp --- saved above.
  sd s1,  0x0038(sp)
  sd a0,  0x0040(sp)
  sd a1,  0x0048(sp)
  sd a2,  0x0050(sp)
  sd a3,  0x0058(sp)
  sd a4,  0x0060(sp)
  sd a5,  0x0068(sp)
  sd a6,  0x0070(sp)
  sd a7,  0x0078(sp)
  sd s2,  0x0080(sp)
  sd s3,  0x0088(sp)
  sd s4,  0x0090(sp)
  sd s5,  0x0098(sp)
  sd s6,  0x00a0(sp)
  sd s7,  0x00a8(sp)
  sd s8,  0x00b0(sp)
  sd s9,  0x00b8(sp)
  sd s10, 0x00c0(sp)
  sd s11, 0x00c8(sp)
  sd t3,  0x00d0(sp)
  sd t4,  0x00d8(sp)
  sd t5,  0x00e0(sp)
  sd t6,  0x00e8(sp)

  # Save SPP and SPIE in case we hit another interrupt (e.g. a nested interrupt
  # [unusual], an interrupt while processing a defint, or do a context switch).
  # We must not trap above!
  csrr t0, sstatus
  andi t0, t0, SSTATUS_SAVE_MASK
  sd t0, 0x0008(sp)

  csrr a0, scause
  csrr a1, stval
  csrr a2, sepc
  csrr a3, sstatus
  andi a3, a3, SSTATUS_SPP

  call int_handler

  # Restore SSTATUS_SPIE and SPP.  Clear them, then set from saved state.
  # TODO(aoates): write tests that catch all save/restore possibilities.
  li t0, SSTATUS_SAVE_MASK
  csrc sstatus, t0
  ld t0, 0x0008(sp)
  csrs sstatus, t0

  # ra: we'll do ra later.
  # sp: no need to save/restore it
  ld gp,  0x0010(sp)
  ld tp,  0x0018(sp)
  ld t0,  0x0020(sp)
  ld t1,  0x0028(sp)
  ld t2,  0x0030(sp)
  # Skip s0/fp --- saved above.
  ld s1,  0x0038(sp)
  ld a0,  0x0040(sp)
  ld a1,  0x0048(sp)
  ld a2,  0x0050(sp)
  ld a3,  0x0058(sp)
  ld a4,  0x0060(sp)
  ld a5,  0x0068(sp)
  ld a6,  0x0070(sp)
  ld a7,  0x0078(sp)
  ld s2,  0x0080(sp)
  ld s3,  0x0088(sp)
  ld s4,  0x0090(sp)
  ld s5,  0x0098(sp)
  ld s6,  0x00a0(sp)
  ld s7,  0x00a8(sp)
  ld s8,  0x00b0(sp)
  ld s9,  0x00b8(sp)
  ld s10, 0x00c0(sp)
  ld s11, 0x00c8(sp)
  ld t3,  0x00d0(sp)
  ld t4,  0x00d8(sp)
  ld t5,  0x00e0(sp)
  ld t6,  0x00e8(sp)

  # Restore the saved frame pointer from our stack frame.
  ld fp, 256(sp)
  # Load from our stack frame the interrupted address into sepc.  If we weren't
  # interrupted again, this in unnecessary.
  ld ra, 264(sp)
  csrw sepc, ra
  # Restore the original value of the ra address (from the interrupted code)
  ld ra, 0(sp)
  ld sp, 248(sp)
  sret

_int_handlers_end:
