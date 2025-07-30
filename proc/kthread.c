// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <stdint.h>

#include "arch/memory/page_map.h"
#include "arch/proc/kthread-stack.h"
#include "arch/proc/kthread.h"
#include "common/atomic.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/per_cpu.h"
#include "common/refcount.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "memory/memory.h"
#include "proc/defint.h"
#include "proc/kthread-queue.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/raw_spinlock.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "proc/thread_annotations.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_thread.h"
#endif

#define KTHREAD_STACK_PROTECT_LEN PAGE_SIZE
#define KTHREAD_STACK_SIZE \
  (ARCH_KTHREAD_BASE_STACK_SIZE + KTHREAD_STACK_PROTECT_LEN)

static DECLARE_PER_CPU(kthread_data_t*, g_current_thread) = 0;
static DECLARE_PER_CPU(kthread_data_t*, g_last_thread) = 0;
static int g_next_id = 0;
static list_t g_all_threads = LIST_INIT_STATIC;

// A queue of threads that have exited and we can clean up.
static kthread_queue_t g_reap_queue;

static void kthread_init_kthread(kthread_data_t* t) {
  t->spin = KSPINLOCK_INTERRUPT_SAFE_INIT;
  kspin_int_constructor(&t->spin);
  t->ref = REFCOUNT_INIT;
  t->state = KTHREAD_PENDING;
  t->id = 0;
  t->retval = 0x0;
  t->prev = t->next = 0x0;
  t->queue = 0x0;
  t->stack = 0x0;
  atomic_store_relaxed(&t->runnable, 1);
  kthread_queue_init(&t->join_list);
  t->process = 0x0;
  ksigemptyset(&t->signal_mask);
  ksigemptyset(&t->assigned_signals);
  kmemset(&t->syscall_ctx, 0, sizeof(syscall_context_t));
  t->interruptable = false;
  t->wait_status = SWAIT_DONE;
  t->wait_timeout_ran = false;
  // TODO(aoates): enable preemption by default.
  atomic_store_relaxed(&t->preemption_disables, 1);
  t->spinlocks_held = 0;
  t->all_threads_link = LIST_LINK_INIT;
  t->proc_threads_link = LIST_LINK_INIT;
  atomic_store_relaxed(&t->interrupt_level, 0);
#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  t->mutexes_held = LIST_INIT;
#endif
#if ENABLE_TSAN
  t->legacy_interrupt_sync = true;
#endif
}

static void kthread_trampoline(void* (*start_routine)(void*), void* arg)
    NO_THREAD_SAFETY_ANALYSIS {
  // Assert that interrupts are disabled upon entry.
  KASSERT(!interrupts_enabled());

  kthread_data_t* last_thread = PER_CPU(g_last_thread);
  kthread_data_t* current_thread = kthread_current_thread();

  // Set up metadata to match the locks.
  KASSERT(current_thread->spinlocks_held == 0);
  current_thread->spinlocks_held = 2;

  // Unlock both the thread we switched from and the current (new) thread.
  // Pass 0 for the state to prevent interrupt state restoration.
  kspin_unlock_int2(&last_thread->spin, 0);
  kspin_unlock_int2(&current_thread->spin, 0);

  // Enable interrupts now that we are in the generic trampoline and locks are released.
  enable_interrupts();

  // Enable deferred interrupts for all new threads.
  defint_set_state(true);

#if ENABLE_TSAN
  // Acquire the global scheduler lock.  This is to make it so that if a
  // non-preemptible thread creates a new thread then blocks, the new thread
  // will see published values after the blocking.  More generally we could
  // acquire the scheduler implicit lock every time a thread is scheduled ---
  // this reflects the actual behavior of the underlying system, but might mask
  // bugs.
  // TODO(preemption): delete this when all code is preemptible (and uses
  // locking correctly).
  scheduler_tsan_acquire();
#endif

  void* retval = start_routine(arg);
  kthread_exit(retval);
  // Should never get here.
  KASSERT(0);
}

void kthread_init(void) {
  kthread_arch_init();

  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(PER_CPU(g_current_thread) == 0);

  kthread_data_t* first = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  KASSERT(first != 0x0);
  kthread_init_kthread(first);
  kspin_int_constructor(&first->spin);
  first->state = KTHREAD_RUNNING;
  first->id = g_next_id++;
  first->stack = (addr_t*)get_global_meminfo()->thread0_stack.base;
  first->stacklen = get_global_meminfo()->thread0_stack.len;
  list_push(&g_all_threads, &first->all_threads_link);
#if ENABLE_TSAN
  tsan_thread_create(first);
#endif

  KASSERT_DBG((addr_t)(&first) < (addr_t)first->stack + first->stacklen);

  kthread_queue_init(&g_reap_queue);

  PER_CPU(g_current_thread) = first;
  kthread_arch_set_current_thread(first);
  POP_INTERRUPTS();
}

NO_SANITIZER
kthread_t kthread_current_thread(void) {
  return PER_CPU(g_current_thread);
}

// TODO(aoates): reconsider the notion of unattached "kernel" threads ---
// they're efficient (no need to swap address spaces when they run), but are
// weird; they can live/run in any address space/file descriptor space/etc.
int kthread_create(kthread_t* thread_ptr, void* (*start_routine)(void*),
                   void* arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* thread = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  *thread_ptr = thread;

  kthread_init_kthread(thread);
  kspin_int_constructor(&thread->spin);
  thread->id = g_next_id++;
  thread->state = KTHREAD_PENDING;
  thread->retval = 0x0;
  list_push(&g_all_threads, &thread->all_threads_link);

  // Allocate a stack for the thread.
  addr_t* stack = (addr_t*)kmalloc_aligned(KTHREAD_STACK_SIZE, PAGE_SIZE);
  KASSERT(stack != 0x0);

  // Touch each page of the stack to make sure it's paged in.  If we don't do
  // this, when we try to use the stack, we'll cause a page fault, which will in
  // turn cause a double (then triple) fault when IT tries to use the stack.
  _Static_assert(KTHREAD_STACK_SIZE % PAGE_SIZE == 0, "Bad KTHREAD_STACK_SIZE");
  for (addr_t i = 0; i < KTHREAD_STACK_SIZE / PAGE_SIZE; ++i) {
    *((uint8_t*)stack + i * PAGE_SIZE) = 0xAA;
  }
  *((uint8_t*)stack + KTHREAD_STACK_SIZE - 1) = 0xAA;

  // Explicitly make the bottom page of the stack read-only for protection.
  page_frame_remap_virtual((addr_t)stack, MEM_PROT_READ, MEM_ACCESS_KERNEL_ONLY,
                           MEM_GLOBAL);

  thread->stack = stack;
  thread->stacklen = KTHREAD_STACK_SIZE;
  kthread_arch_init_thread(thread, kthread_trampoline, start_routine, arg);

  // TODO(aoates): rather than having this and legacy_interrupt_sync, etc be
  // implicitly copied from parent thread, add thread creation flags to make it
  // explicit.

  kthread_t me = kthread_current_thread();
  // Safe to load relaxed; this is atomic for signal handlers, not concurrency.
  int preemption_disables = atomic_load_relaxed(&me->preemption_disables);
  KASSERT_DBG(preemption_disables >= me->spinlocks_held);
  // If the only reason preemption is disabled is the spinlocks we've held, make
  // the child preemptible.
  if (preemption_disables - me->spinlocks_held == 0) {
    atomic_store_relaxed(&thread->preemption_disables, 0);
  }
#if ENABLE_TSAN
  thread->legacy_interrupt_sync =
      kthread_current_thread()->legacy_interrupt_sync;
  tsan_thread_create(thread);
#endif

  // Create a reference for the thread execution itself, to be released when the
  // thread exits.
  kthread_ref(thread);

  POP_INTERRUPTS();
  return 0;
}

void kthread_destroy(kthread_t thread) {
  kspin_int_destructor(&thread->spin);
  KASSERT(thread->state == KTHREAD_DONE);
  KASSERT(refcount_get(&thread->ref) == 0);
  PUSH_AND_DISABLE_INTERRUPTS();
  list_remove(&g_all_threads, &thread->all_threads_link);
  POP_INTERRUPTS();

#if ENABLE_TSAN
  tsan_thread_destroy(thread);
#endif

  // Write gargbage to crash anyone that tries to use the thread later.
  kmemset(&thread->context, 0xAB, sizeof(kthread_arch_context_t));
  thread->state = KTHREAD_DESTROYED;
  if (thread->stack) {
    page_frame_remap_virtual((addr_t)thread->stack,
                             MEM_PROT_READ | MEM_PROT_WRITE,
                             MEM_ACCESS_KERNEL_ONLY, MEM_GLOBAL);
    kfree(thread->stack);
    thread->stack = 0x0;
  }

  kfree(thread);
}

void kthread_detach(kthread_t thread_ptr) {
  kthread_unref(thread_ptr);
}

void* kthread_join(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  PUSH_AND_DISABLE_INTERRUPTS();
  // Note: we cast this to a kspinlock_t since the scheduler doesn't support
  // waiting on an interrupt-safe spinlock.  This is safe because,
  //  1) interrupt-safe spinlocks are strictly more protective than normal ones
  //  2) we never access join_list from an interrupt context
  //  3) interrupts are already disabled anyway
  // Therefore, any simultaneous accesses to join_list (or other thread state)
  // must be happening on another SMP core, and therefore protected by the
  // actual spinning part of the spinlock.
  kspin_lock((kspinlock_t*)&thread->spin);
  KASSERT(thread->state == KTHREAD_PENDING ||
          thread->state == KTHREAD_DONE);

  if (thread->state != KTHREAD_DONE) {
    scheduler_wait_on_splocked(&thread->join_list, -1,
                               (kspinlock_t*)&thread->spin);
  }
  KASSERT(thread->state == KTHREAD_DONE);
  void* retval = thread->retval;
  kspin_unlock((kspinlock_t*)&thread->spin);
  POP_INTERRUPTS();

#if ENABLE_TSAN
  tsan_thread_join(thread_ptr);
#endif
  // Return our reference.  This will free the thread if we're last.
  kthread_unref(thread);
  return retval;
}

bool kthread_is_done(kthread_t thread) {
  kspin_lock_int(&thread->spin);
  bool result = thread->state == KTHREAD_DONE;
  kspin_unlock_int(&thread->spin);
  return result;
}

void kthread_exit(void* x) {
  kthread_t thread = PER_CPU(g_current_thread);
  kspin_lock_int(&thread->spin);
  KASSERT(thread->spinlocks_held == 1);
  KASSERT(thread->process == NULL);

  // kthread_exit is basically the same as kthread_yield, but we don't put
  // ourselves back on the run queue.
  thread->retval = x;
  thread->state = KTHREAD_DONE;

  // Schedule all the waiting threads.
  scheduler_wake_all(&thread->join_list);
  kspin_unlock_int(&thread->spin);

  // Transfer our reference to the reap queue.
  kthread_queue_push(&g_reap_queue, thread);

  scheduler_yield_no_reschedule();

  // Never get here!
  KASSERT(0);
}

void kthread_run_on_all(void (*f)(kthread_t, void*), void* arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  for (list_link_t* link = g_all_threads.head; link != NULL;
       link = link->next) {
    kthread_t thread =
        container_of(link, struct kthread_data, all_threads_link);
    f(thread, arg);
  }
  POP_INTERRUPTS();
}

void kthread_reset_interrupt_level(void) {
  int ilevel = atomic_load_relaxed(&PER_CPU(g_current_thread)->interrupt_level);
  KASSERT(ilevel == 0 || ilevel == 1);
  atomic_store_relaxed(&PER_CPU(g_current_thread)->interrupt_level, 0);

#if ENABLE_TSAN
  // Before we return to user-mode, release all writes above to the interrupt
  // thread.  Because interrupts are blocked, they wouldn't otherwise be
  // released.
  tsan_release(NULL, TSAN_INTERRUPTS);
#endif
}

void kthread_disable(kthread_t thread) {
  atomic_store_relaxed(&thread->runnable, 0);
}

void kthread_enable(kthread_t thread) {
  atomic_store_relaxed(&thread->runnable, 1);
}

static void assert_locked(const kspinlock_intsafe_t* l, kthread_id_t holder)
    ASSERT_CAPABILITY(l) {
  KASSERT(l->_lock.holder == holder);
}

// NO_TSAN: this manipulates the current thread execution state, which confuses
// TSAN for accesses that happen inside the function.
// TODO(aoates): figure out a way to have TSAN enabled for this function, or
// most of it.
NO_TSAN void kthread_switch(kthread_t new_thread) NO_THREAD_SAFETY_ANALYSIS {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_id_t my_id = PER_CPU(g_current_thread)->id;
  defint_state_t defint = defint_state();

  kthread_data_t* old_thread = PER_CPU(g_current_thread);

  if (old_thread == new_thread) {
    POP_INTERRUPTS();
    return;
  }

  // Lock both threads in a consistent order to prevent deadlocks.
  kspinstate_t outer_lock_state;
  if (old_thread->id < new_thread->id) {
    outer_lock_state = kspin_lock_int(&old_thread->spin);
    kspin_lock_int(&new_thread->spin);
  } else {
    outer_lock_state = kspin_lock_int(&new_thread->spin);
    kspin_lock_int(&old_thread->spin);
  }

  PER_CPU(g_last_thread) = old_thread;

#if ENABLE_TSAN
  // All writes should now be visible to the interrupt thread.  This is only
  // relevant for (a) writes in thread exit paths (which may touch memory that
  // is freed then reused), and (b) writes in kthread/scheduler internals.
  // Since we don't have a synchronizing POP_INTERRUPTS() before we actually
  // switch threads, do one explicitly here to release all our writes.
  interrupt_do_legacy_full_sync(/* is_acquire */ false);
  // TODO(tsan): once all code is updated to use spinlocks and the kernel is
  // SMP-safe, see if we can remove this.
#endif
  if (old_thread->state != KTHREAD_DONE) {
    KASSERT_DBG(old_thread->state == KTHREAD_YIELDING);
    old_thread->state = KTHREAD_PENDING;
  }

  PER_CPU(g_current_thread) = new_thread;
  kthread_arch_set_current_thread(PER_CPU(g_current_thread));
  new_thread->state = KTHREAD_RUNNING;

  // If either the old or new thread isn't owned by a process (as with some
  // kernel threads), either unconditionally switch to the new thread's address
  // space, or continue executing in whatever address space we're already in.
  // TODO(aoates): should we really allow orphan threads like this?  Or should
  // we require all such threads to be tied to the root process?  It's a little
  // weird that these threads can end up executing in arbitrary address spaces.
  const page_dir_ptr_t old_pd =
      (old_thread->process ? old_thread->process->page_directory : 0x0);
  const page_dir_ptr_t new_pd =
      (new_thread->process ? new_thread->process->page_directory : old_pd);
  if (new_thread->process) {
    proc_set_current(new_thread->process);
  }
  kthread_arch_swap_context(old_thread, new_thread, old_pd, new_pd);

#if ENABLE_TSAN
  interrupt_do_legacy_full_sync(/* is_acquire */ true);
#endif

  // After context_swap RETURNS, we are running as the old thread again.
  // Unlock both the thread we switched from and ourselves.
  kthread_t actual_last_thread = PER_CPU(g_last_thread);
  assert_locked(&actual_last_thread->spin, actual_last_thread->id);
  kspin_unlock_int2(&actual_last_thread->spin, 0);
  kspin_unlock_int2(&old_thread->spin, outer_lock_state);

  // Verify that we're back on the proper stack!
  KASSERT(PER_CPU(g_current_thread)->id == my_id);

  defint_set_state(defint);

  // Clean up any thread stacks waiting to be reaped.
  raw_spin_lock(&g_reap_queue.spin);
  kthread_t reap_list = g_reap_queue.head;
  g_reap_queue.head = g_reap_queue.tail = NULL;
  raw_spin_unlock(&g_reap_queue.spin);

  while (reap_list) {
    kthread_t next = reap_list->next;
    kthread_unref(reap_list);
    reap_list = next;
  }

  POP_INTERRUPTS();
}

// NO_SANITIZER: because this function is used by TSAN to determine current
// execution state.
NO_SANITIZER
ktctx_type_t kthread_execution_context(void) {
  // Before kthread is initialized, just assume we're always in a thread ctx.
  if (!PER_CPU(g_current_thread)) return KTCTX_THREAD;

  defint_running_t s = defint_running_state();
  int int_level = atomic_load_relaxed(&PER_CPU(g_current_thread)->interrupt_level);
  if (s == DEFINT_NONE) {
    return (int_level > 0) ? KTCTX_INTERRUPT : KTCTX_THREAD;
  } else if (s == DEFINT_THREAD_CTX) {
    return (int_level > 0) ? KTCTX_INTERRUPT : KTCTX_DEFINT;
  } else {
    KASSERT_DBG(s == DEFINT_INTERRUPT_CTX);
    return (int_level > 1) ? KTCTX_INTERRUPT : KTCTX_DEFINT;
  }
}
