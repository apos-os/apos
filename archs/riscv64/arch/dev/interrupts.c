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
#include "common/atomic.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/interrupts.h"
#include "internal/constants.h"
#include "internal/plic.h"
#include "memory/vm_page_fault.h"
#include "proc/defint.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/user_prepare.h"
#include "sanitizers/tsan/tsan_lock.h"
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

static void sigill_handler(bool is_kernel, addr_t addr, uint64_t instr) {
  klogf("Illegal instruction at address 0x%" PRIxADDR " (instruction: 0x%lx)\n",
        addr, (unsigned long)instr);
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

static void rsv_software_interrupt(rsv_context_t* ctx) {
  asm volatile("csrci sip, 0x2");
  switch (ctx->a0) {
    case RSV_SOFTINT_PREEMPT:
      sched_tick();
      break;

    default:
      // These should never be generated (currently).
      die("Unexpected software interrupt");
  }
}

void interrupts_init(void) {
  // Enable timer interupts by setting STIE.
  // TODO(aoates): consider safer boot sequence and not enabling these until
  // timers are fully set up.
  uint64_t sie_bits = 0x22;
  asm volatile("csrs sie, %0" ::"r"(sie_bits));
}

static user_context_t copy_ctx(void* ctx_ptr) {
  return *(const user_context_t*)ctx_ptr;
}

// NO_TSAN: because this function manipulates interrupt_level, which is itself
// used by TSAN to determine current execution state.
void NO_TSAN int_handler(rsv_context_t* ctx, uint64_t scause, uint64_t stval,
                         uint64_t is_kernel) {
  kthread_t thread = kthread_current_thread();
  if (thread) {
    int val = atomic_add_relaxed(&thread->interrupt_level, 1);
    KASSERT_DBG(val == 1 || val == 2);
#if ENABLE_TSAN
    // "Release" the interrupt lock --- everything past this should be
    // considered a new epoch for the interrupt thread.
    tsan_release(NULL, TSAN_INTERRUPTS);
#endif
  }

  klogfm(KL_GENERAL, DEBUG3,
         "interrupt: scause: 0x%lx  stval: 0x%lx  sepc: 0x%lx  is_kernel: %d\n",
         scause, stval, ctx->address, (int)is_kernel);

  syscall_context_t* syscall_ctx = NULL;
  bool is_interrupt = true;
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
        KASSERT_DBG(is_kernel);
        rsv_software_interrupt(ctx);
        break;

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
        sigill_handler(is_kernel, ctx->address, stval);
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
        KASSERT_DBG(atomic_load_relaxed(&thread->interrupt_level) == 1);
        atomic_store_relaxed(&thread->interrupt_level, 0);
        is_interrupt = false;
        enable_interrupts();
        ctx->a0 = syscall_dispatch(ctx->a0, ctx->a1, ctx->a2, ctx->a3, ctx->a4,
                                   ctx->a5, ctx->a6);
        ctx->address += RSV_ECALL_INSTR_LEN;
        syscall_ctx = &kthread_current_thread()->syscall_ctx;
        disable_interrupts();
        break;

      case RSV_TRAP_BREAKPOINT:
      case RSV_TRAP_ENVCALL_SUP:
      default:
        klogfm(KL_GENERAL, FATAL,
               "Unhandled trap %d (stval: 0x%lx  sepc: 0x%lx  is_kernel: %d)\n",
               (int)scause, stval, ctx->address, (int)is_kernel);
    }
  }

  defint_process_queued(/* force */ true);

  if (thread && is_interrupt) {
    KASSERT_DBG(atomic_load_relaxed(&thread->interrupt_level) >= 1);
    atomic_sub_relaxed(&thread->interrupt_level, 1);
  }

  if (!is_kernel) {
    proc_prep_user_return(&copy_ctx, ctx, syscall_ctx);

#if ENABLE_TSAN
    // Before we return to user-mode, release all writes above to the interrupt
    // thread.  Because interrupts are blocked, they wouldn't otherwise be
    // released.
    tsan_release(NULL, TSAN_INTERRUPTS);
#endif
  }

  // Note: we may never get here, if there were signals to dispatch.
}

#if ENABLE_TSAN

// For legacy code that uses PUSH_AND_DISABLE_INTERRUPTS() and friends, we need
// to model each of those calls as a synchronization between threads.  This is
// the virtual global "lock" we use to model that.
static tsan_lock_data_t g_interrupt_lock = TSAN_LOCK_DATA_INIT;

bool interrupt_set_legacy_full_sync(bool full_sync) {
  kthread_t t = kthread_current_thread();
  bool old = t->legacy_interrupt_sync;
  t->legacy_interrupt_sync = full_sync;
  return old;
}

void interrupt_do_legacy_full_sync(bool is_acquire) {
  kthread_t t = kthread_current_thread();
  if (!t) return;

  if (is_acquire) {
    tsan_acquire(NULL, TSAN_INTERRUPTS);
    if (t->legacy_interrupt_sync) {
      tsan_acquire(&g_interrupt_lock, TSAN_LOCK);
    }
  } else {
    tsan_release(NULL, TSAN_INTERRUPTS);
    if (t->legacy_interrupt_sync) {
      tsan_release(&g_interrupt_lock, TSAN_LOCK);
    }
  }
}

void enable_interrupts(void) {
  tsan_release(NULL, TSAN_INTERRUPTS);
  enable_interrupts_raw();
}

void disable_interrupts(void) {
  disable_interrupts_raw();
  tsan_acquire(NULL, TSAN_INTERRUPTS);
}

interrupt_state_t save_and_disable_interrupts(bool full_sync) {
  interrupt_state_t ret = save_and_disable_interrupts_raw();
  tsan_acquire(NULL, TSAN_INTERRUPTS);
  kthread_t t = kthread_current_thread();
  if (full_sync && t && t->legacy_interrupt_sync) {
    tsan_acquire(&g_interrupt_lock, TSAN_LOCK);
  }
  return ret;
}

void restore_interrupts(interrupt_state_t saved, bool full_sync) {
  // Be conservative --- only publish values to interrupts if we're actually
  // enabling interrupts here.  This is not required for correctness, but
  // correct could should not be sensitive to this.
  if (saved) {
    tsan_release(NULL, TSAN_INTERRUPTS);
    kthread_t t = kthread_current_thread();
    if (full_sync && t && t->legacy_interrupt_sync) {
      tsan_release(&g_interrupt_lock, TSAN_LOCK);
    }
  }
  restore_interrupts_raw(saved);
}

#endif  // ENABLE_TSAN
