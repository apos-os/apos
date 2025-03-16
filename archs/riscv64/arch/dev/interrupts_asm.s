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
  # If interrupted user mode, switch stacks.
  beqz s2, .Luser_stack_switch

  # If interrupted kernel mode, use our stack as-is.  First, check if we
  # interrupted the prologue of this function --- that indicates a double fault
  # (and likely stack overflow in one of the below instructions).

  # Read sepc and store s3 into sepc for now.
  csrrw s3, sepc, s3

  # Check if we interrupted between int_handler_asm and the end of the prologue
  # --- though if we interrupted between int_handler_asm and here, we're
  # probably screwed no matter what (as it means $sscratch was invalid), and
  # likely won't even get here.
  lla s2, int_handler_asm
  bltu s3, s2, .Lkernel_stack_safe     # if ($sepc < int_handler_asm) goto safe
  lla s2, .Lint_handler_prologue_done
  bgeu s3, s2, .Lkernel_stack_safe     # if ($sepc >= $prologue_end) goto safe

  # Womp, double fault.  Switch stacks and go to the double fault handler.
  # First, set up a fake stack frame for the interrupted code, and one for
  # int_handler that double faulted.
  # Clobber registers freely at this point, we're not going back.
  mv a0, s3  # arg0 = interrupted address
  mv a1, sp  # arg1 = interrupted stack pointer
  la sp, g_dblfault_stack
  li t0, RSV64_DBLFAULT_STACK_SIZE
  add sp, sp, t0
  addi sp, sp, RSV64_KSTACK_SCRATCH_NBYTES  # Just for consistency...

  # First stack frame --- original interrupted code.
  ld t0, -16(s1)  # Get original interrupted address.
  addi sp, sp, -16
  sd fp, 0(sp)
  sd t0, 8(sp)
  addi fp, sp, 16

  # Second stack frame --- the int_handler_asm code.
  addi t0, a0, 4  # t0 = a0 + SIZE_OF_JUMP_INSTR
  addi sp, sp, -16
  sd fp, 0(sp)
  sd t0, 8(sp)
  addi fp, sp, 16

  la t0, rsv_dblfault_handler
  jalr t0
  # Can't get here.
.Lloop:
  wfi
  j .Lloop

.Lkernel_stack_safe:
  sd s3, -16(s1)      # Store the original sepc into our scratch space.
  csrrw s3, sepc, s3  # Swap sepc and s3 back
  j .Lstack_done

.Luser_stack_switch:
  # We interrupted user mode and need to switch stacks.  sscratch is the bottom
  # (highest address) of the kernel stack, so start right after that.
  mv sp, s1  # Original sp saved above.
  addi sp, sp, RSV64_KSTACK_SCRATCH_NBYTES

.Lstack_done:
  # New state: sp is believed to be a valid kernel stack.  First, restore
  # sscratch before we actually _use_ sp, in case we double fault.
  mv s2, s1               # Save scratch ptr into s2.
  csrrw s1, sscratch, s1  # Restore s1 and sscratch.

  # Save original s1 value onto new stack.  If we're overflowing the kernel
  # stack, this will trap (first opportunity, if sscratch was valid).
  sd s1, -224(sp)         # Save original s1 onto new stack (in context struct)

  ld s1, -8(s2)
  sd s1, -280(sp)         # Save original sp onto new stack.
  ld s2, 0(s2)            # Get saved s2 from the scratch spot.
  # Now everything is as it was, except we may have switched stacks.

  addi sp, sp, -288
  # Save the original ra value as a local variable.  We need to restore it
  # later, but if the code we interrupted is a leaf function, this ra likely
  # points to _its_ caller, so if we use it for our stack frame it will look
  # like we skipped the function that was actually called.
  sd ra, 0(sp)
  # Now pretend as if the interrupted code called us.
  csrr ra, sepc
  # Now create the start of our standard stack frame.
  sd ra, 280(sp)
  sd fp, 272(sp)
  sd fp, 0x038(sp)  # Store in ctx->fp as well.
  addi fp, sp, 288  # fake frame

  # Now save all our other registers, creating an rsv_context_t on the stack.
  # ra: is already stored at 0(sp)
  # sp: stored above
  sd gp,  0x010(sp)
  sd tp,  0x018(sp)
  sd t0,  0x020(sp)
  sd t1,  0x028(sp)
  sd t2,  0x030(sp)
  # fp/s0 stored above.
  # s1 stored above.
  sd a0,  0x048(sp)
  sd a1,  0x050(sp)
  sd a2,  0x058(sp)
  sd a3,  0x060(sp)
  sd a4,  0x068(sp)
  sd a5,  0x070(sp)
  sd a6,  0x078(sp)
  sd a7,  0x080(sp)
  sd s2,  0x088(sp)
  sd s3,  0x090(sp)
  sd s4,  0x098(sp)
  sd s5,  0x0a0(sp)
  sd s6,  0x0a8(sp)
  sd s7,  0x0b0(sp)
  sd s8,  0x0b8(sp)
  sd s9,  0x0c0(sp)
  sd s10, 0x0c8(sp)
  sd s11, 0x0d0(sp)
  sd t3,  0x0d8(sp)
  sd t4,  0x0e0(sp)
  sd t5,  0x0e8(sp)
  sd t6,  0x0f0(sp)

  # Save sepc to ctx->address.
  csrr t0, sepc
  sd t0, 0x0f8(sp)

  # Save SPP and SPIE in case we hit another interrupt (e.g. a nested interrupt
  # [unusual], an interrupt while processing a defint, or do a context switch).
  # We must not trap above!
  csrr t0, sstatus
  andi t0, t0, SSTATUS_SAVE_MASK
  sd t0, 0x100(sp)

.Lint_handler_prologue_done:
  mv a0, sp  # Pass &ctx
  csrr a1, scause
  csrr a2, stval
  csrr a3, sstatus
  andi a3, a3, SSTATUS_SPP

  call int_handler

  # Restore SSTATUS_SPIE and SPP.  Clear them, then set from saved state.
  # TODO(aoates): write tests that catch all save/restore possibilities.
  li t0, SSTATUS_SAVE_MASK
  csrc sstatus, t0
  ld t0, 0x0100(sp)
  csrs sstatus, t0

  # ra and sp: we'll do later.
  ld gp,  0x010(sp)
  ld tp,  0x018(sp)
  ld t0,  0x020(sp)
  ld t1,  0x028(sp)
  ld t2,  0x030(sp)
  ld s0,  0x038(sp)
  ld s1,  0x040(sp)
  ld a0,  0x048(sp)
  ld a1,  0x050(sp)
  ld a2,  0x058(sp)
  ld a3,  0x060(sp)
  ld a4,  0x068(sp)
  ld a5,  0x070(sp)
  ld a6,  0x078(sp)
  ld a7,  0x080(sp)
  ld s2,  0x088(sp)
  ld s3,  0x090(sp)
  ld s4,  0x098(sp)
  ld s5,  0x0a0(sp)
  ld s6,  0x0a8(sp)
  ld s7,  0x0b0(sp)
  ld s8,  0x0b8(sp)
  ld s9,  0x0c0(sp)
  ld s10, 0x0c8(sp)
  ld s11, 0x0d0(sp)
  ld t3,  0x0d8(sp)
  ld t4,  0x0e0(sp)
  ld t5,  0x0e8(sp)
  ld t6,  0x0f0(sp)

  # Load from our stack frame the interrupted address into sepc.  If we weren't
  # interrupted again, this in unnecessary.
  ld ra, 0xf8(sp)
  csrw sepc, ra
  # Restore the original value of ra (from the interrupted code) and sp.
  ld ra, 0(sp)
  ld sp, 0x08(sp)
  sret

_int_handlers_end:
