// Copyright 2023 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "arch/dev/interrupts.h"

#include "archs/riscv64/internal/context.h"
#include "archs/riscv64/internal/page_tables.h"
#include "archs/riscv64/internal/riscv.h"
#include "archs/riscv64/internal/timer.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "internal/constants.h"
#include "internal/plic.h"
#include "memory/vm_page_fault.h"
#include "proc/defint.h"
#include "proc/signal/signal.h"
#include "proc/user_prepare.h"
#include "syscall/syscall_dispatch.h"

// Interrupt and trap definitions (per values in scause).
#define RSV_INTERRUPT (1LL << (SXLEN - 1))
#define RSV_INT_SSOFTWARE 1  // Software interrupt
#define RSV_INT_STIMER 5     // Timer interrupt
#define RSV_INT_SEXTERNAL 9  // External interrupt

#define RSV_TRAP_INSTR_MISALIGN 0    // Instruction address misaligned
#define RSV_TRAP_INSTR_ACCESS 1      // Instruction access fault
#define RSV_TRAP_INSTR_ILLEGAL 2     // Illegal instruction
#define RSV_TRAP_BREAKPOINT 3        // Breakpoint
#define RSV_TRAP_LOAD_MISALIGN 4     // Load address misaligned
#define RSV_TRAP_LOAD_ACCESS 5       // Load access fault
#define RSV_TRAP_STORE_MISALIGN 6    // Store/AMO address misaligned
#define RSV_TRAP_STORE_ACCESS 7      // Store/AMO access fault
#define RSV_TRAP_ENVCALL_USR 8       // Environment call from U-mode
#define RSV_TRAP_ENVCALL_SUP 9       // Environment call from S-mode
#define RSV_TRAP_PAGEFAULT_INSTR 12  // Instruction page fault
#define RSV_TRAP_PAGEFAULT_LOAD 13   // Load page fault
#define RSV_TRAP_PAGEFAULT_STORE 15  // Store/AMO page fault

static void sigill_handler(bool is_kernel) {
  if (is_kernel) {
    die("sigill in kernel code");
  }

  KASSERT(proc_force_signal_on_thread(
          proc_current(), kthread_current_thread(), SIGILL) == 0);
}

static void sigbus_handler(bool is_kernel) {
  if (is_kernel) {
    die("sigbus in kernel code");
  }

  KASSERT(proc_force_signal_on_thread(
          proc_current(), kthread_current_thread(), SIGBUS) == 0);
}

static void rsv_page_fault(int trap, addr_t addr, bool is_kernel) {
  rsv_mapsize_t size;
  rsv_sv39_pte_t pte = rsv_lookup_pte(rsv_get_hart_as(), addr, &size);
  vm_fault_type_t type =
      (pte & RSV_PTE_VALID) ? VM_FAULT_ACCESS : VM_FAULT_NOT_PRESENT;

  vm_fault_op_t op;
  // TODO(aoates): support an EXEC fault op.
  switch (trap) {
    case RSV_TRAP_PAGEFAULT_INSTR:
    case RSV_TRAP_PAGEFAULT_LOAD:
      op = VM_FAULT_READ;
      break;

    case RSV_TRAP_PAGEFAULT_STORE:
      op = VM_FAULT_WRITE;
      break;

    default:
      die("bad page fault trap");
  }
  vm_fault_mode_t mode = is_kernel ? VM_FAULT_KERNEL : VM_FAULT_USER;
  // TODO(aoates): figure out if we should do anything with the return value.
  vm_handle_page_fault(addr, type, op,mode);
}

void interrupts_init(void) {
  // Enable timer interupts by setting STIE.
  // TODO(aoates): consider safer boot sequence and not enabling these until
  // timers are fully set up.
  uint64_t sie_bits = 0x20;
  asm volatile("csrs sie, %0" ::"r"(sie_bits));
}

static user_context_t copy_ctx(void* ctx_ptr) {
  return *(const user_context_t*)ctx_ptr;
}

void int_handler(rsv_context_t* ctx, uint64_t scause, uint64_t stval,
                 uint64_t is_kernel) {
  klogfm(KL_GENERAL, DEBUG3,
         "interrupt: scause: 0x%lx  stval: 0x%lx  sepc: 0x%lx  is_kernel: %d\n",
         scause, stval, ctx->address, (int)is_kernel);

  if (scause & RSV_INTERRUPT) {
    const int interrupt = scause & ~RSV_INTERRUPT;
    switch (interrupt) {
      case RSV_INT_STIMER:
        rsv_timer_interrupt();
        break;

      case RSV_INT_SEXTERNAL:
        rsv_external_interrupt();
        break;

      case RSV_INT_SSOFTWARE:
        // These should never be generated (currently).
        die("Unexpected software interrupt");

      default:
        klogfm(
            KL_GENERAL, FATAL,
            "Unhandled interrupt %d (scause: 0x%lx  stval: 0x%lx  sepc: 0x%lx  "
            "is_kernel: %d)\n",
            interrupt, scause, stval, ctx->address, (int)is_kernel);
    }
  } else {
    switch (scause) {
      case RSV_TRAP_PAGEFAULT_INSTR:
      case RSV_TRAP_PAGEFAULT_LOAD:
      case RSV_TRAP_PAGEFAULT_STORE:
        rsv_page_fault(scause, stval, is_kernel);
        break;

      case RSV_TRAP_INSTR_ILLEGAL:
        sigill_handler(is_kernel);
        break;

      case RSV_TRAP_INSTR_MISALIGN:
      case RSV_TRAP_LOAD_MISALIGN:
      case RSV_TRAP_STORE_MISALIGN:
      // We have no reason to cause an access-fault exception today.
      case RSV_TRAP_INSTR_ACCESS:
      case RSV_TRAP_LOAD_ACCESS:
      case RSV_TRAP_STORE_ACCESS:
        sigbus_handler(is_kernel);
        break;

      case RSV_TRAP_ENVCALL_USR:
        ctx->a0 = syscall_dispatch(ctx->a0, ctx->a1, ctx->a2, ctx->a3, ctx->a4,
                                   ctx->a5, ctx->a6);
        ctx->address += RSV_ECALL_INSTR_LEN;
        break;

      case RSV_TRAP_BREAKPOINT:
      case RSV_TRAP_ENVCALL_SUP:
      default:
        klogfm(KL_GENERAL, FATAL,
               "Unhandled trap %d (stval: 0x%lx  sepc: 0x%lx  is_kernel: %d)\n",
               (int)scause, stval, ctx->address, (int)is_kernel);
    }
  }

  defint_process_queued();

  if (!is_kernel) {
    proc_prep_user_return(&copy_ctx, ctx, NULL);
  }

  // Note: we may never get here, if there were signals to dispatch.
}
