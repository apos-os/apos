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
#include "arch/proc/kthread.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "memory/memory.h"
#include "proc/defint.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "sanitizers/tsan/tsan_lock.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_thread.h"
#endif

#define KTHREAD_STACK_PROTECT_LEN PAGE_SIZE
#define KTHREAD_STACK_SIZE \
  (ARCH_KTHREAD_BASE_STACK_SIZE + KTHREAD_STACK_PROTECT_LEN)

static kthread_data_t* g_current_thread = 0;
static int g_next_id = 0;
static list_t g_all_threads = LIST_INIT_STATIC;

// A queue of threads that have exited and we can clean up.
static kthread_queue_t g_reap_queue;

static void kthread_init_kthread(kthread_data_t* t) {
  t->state = KTHREAD_PENDING;
  t->id = 0;
  t->retval = 0x0;
  t->prev = t->next = 0x0;
  t->queue = 0x0;
  t->stack = 0x0;
  t->detached = false;
  t->runnable = true;
  kthread_queue_init(&t->join_list);
  t->join_list_pending = 0;
  t->process = 0x0;
  ksigemptyset(&t->signal_mask);
  ksigemptyset(&t->assigned_signals);
  kmemset(&t->syscall_ctx, 0, sizeof(syscall_context_t));
  t->interruptable = false;
  t->wait_status = SWAIT_DONE;
  t->wait_timeout_ran = false;
  // TODO(aoates): enable preemption by default.
  t->preemption_disables = 1;
  t->spinlocks_held = 0;
  t->all_threads_link = LIST_LINK_INIT;
  t->proc_threads_link = LIST_LINK_INIT;
  t->interrupt_level = 0;
#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  t->mutexes_held = LIST_INIT;
#endif
}

static void kthread_trampoline(void *(*start_routine)(void*), void* arg) {
  // The arch-specific trampoline should have enabled interrupts.
  KASSERT(interrupts_enabled());

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
  KASSERT(g_current_thread == 0);

  kthread_data_t* first = (kthread_data_t*)kmalloc(sizeof(kthread_data_t));
  KASSERT(first != 0x0);
  kthread_init_kthread(first);
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

  g_current_thread = first;
  kthread_arch_set_current_thread(first);
  POP_INTERRUPTS();
}

kthread_t kthread_current_thread(void) {
  return g_current_thread;
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
  thread->id = g_next_id++;
  thread->state = KTHREAD_PENDING;
  thread->retval = 0x0;
  ksigemptyset(&thread->signal_mask);
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

  if (kthread_current_thread()->preemption_disables == 0) {
    thread->preemption_disables = 0;
  }
#if ENABLE_TSAN
  tsan_thread_create(thread);
#endif

  POP_INTERRUPTS();
  return 0;
}

void kthread_destroy(kthread_t thread) {
  KASSERT(thread->state == KTHREAD_DONE);
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
  kthread_data_t* thread = thread_ptr;
  KASSERT(!thread->detached);
  KASSERT(thread->join_list_pending == 0);
  thread->detached = true;
}

void* kthread_join(kthread_t thread_ptr) {
  kthread_data_t* thread = thread_ptr;
  KASSERT(thread->state == KTHREAD_PENDING ||
          thread->state == KTHREAD_DONE);
  KASSERT(!thread->detached);

  if (thread->state != KTHREAD_DONE) {
    thread->join_list_pending++;
    scheduler_wait_on(&thread->join_list);
    thread->join_list_pending--;
  }
#if ENABLE_TSAN
  tsan_thread_join(thread_ptr);
#endif
  KASSERT(thread->state == KTHREAD_DONE);
  void* retval = thread->retval;
  // If we're last, clean up after the thread.
  if (thread->join_list_pending == 0) {
    kthread_destroy(thread);
  }
  return retval;
}

bool kthread_is_done(kthread_t thread) {
  return thread->state == KTHREAD_DONE;
}

void kthread_exit(void* x) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_current_thread->spinlocks_held == 0);
  KASSERT(g_current_thread->process == NULL);

  // kthread_exit is basically the same as kthread_yield, but we don't put
  // ourselves back on the run queue.
  g_current_thread->retval = x;
  g_current_thread->state = KTHREAD_DONE;

  // Schedule all the waiting threads.
  scheduler_wake_all(&g_current_thread->join_list);

  if (g_current_thread->detached) {
    kthread_queue_push(&g_reap_queue, g_current_thread);
  }

  scheduler_yield_no_reschedule();

  // Never get here!
  KASSERT(0);
  POP_INTERRUPTS();
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
  KASSERT(g_current_thread->interrupt_level == 0 ||
          g_current_thread->interrupt_level == 1);
  g_current_thread->interrupt_level = 0;
}

void kthread_disable(kthread_t thread) {
  thread->runnable = false;
}

void kthread_enable(kthread_t thread) {
  thread->runnable = true;
}

void kthread_switch(kthread_t new_thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_current_thread->state != KTHREAD_RUNNING);
  kthread_id_t my_id = g_current_thread->id;
  defint_state_t defint = defint_state();

#if ENABLE_TSAN
  // All writes should now be visible to the interrupt thread.  This is only
  // relevant for (a) writes in thread exit paths (which may touch memory that
  // is freed then reused), and (b) writes in kthread/scheduler internals.
  // TODO(tsan): once all code is updated to use spinlocks and the kernel is
  // SMP-safe, see if we can remove this.
  tsan_release(NULL, TSAN_INTERRUPTS);
#endif

  kthread_data_t* old_thread = g_current_thread;
  g_current_thread = new_thread;
  kthread_arch_set_current_thread(g_current_thread);
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

  // Verify that we're back on the proper stack!
  KASSERT(g_current_thread->id == my_id);

  defint_set_state(defint);

  // Clean up any thread stacks waiting to be reaped.
  kthread_t t = kthread_queue_pop(&g_reap_queue);
  while (t) {
    kthread_destroy(t);
    t = kthread_queue_pop(&g_reap_queue);
  }

  POP_INTERRUPTS();
}

ktctx_type_t kthread_execution_context(void) {
  // Before kthread is initialized, just assume we're always in a thread ctx.
  if (!g_current_thread) return KTCTX_THREAD;

  defint_running_t s = defint_running_state();
  int int_level = g_current_thread->interrupt_level;
  if (s == DEFINT_NONE) {
    return (int_level > 0) ? KTCTX_INTERRUPT : KTCTX_THREAD;
  } else if (s == DEFINT_THREAD_CTX) {
    return (int_level > 0) ? KTCTX_INTERRUPT : KTCTX_DEFINT;
  } else {
    KASSERT_DBG(s == DEFINT_INTERRUPT_CTX);
    return (int_level > 1) ? KTCTX_INTERRUPT : KTCTX_DEFINT;
  }
}

void kthread_queue_init(kthread_queue_t* lst) {
  lst->head = lst->tail = 0x0;
}

// Inserts the node B into the linked list right after A.
static void kthread_queue_insert(kthread_data_t* A, kthread_data_t* B) {
  B->next = A->next;
  B->prev = A;
  if (A->next) {
    A->next->prev = B;
  }
  A->next = B;
}

// Push a thread onto the end of a list.
void kthread_queue_push(kthread_queue_t* lst, kthread_data_t* thread) {
  KASSERT(thread->prev == 0);
  KASSERT(thread->next == 0);
  KASSERT(thread->queue == NULL);

  if (!lst->head) {
    KASSERT(lst->tail == 0x0);
    lst->head = lst->tail = thread;
    thread->prev = thread->next = 0x0;
  } else {
    if (lst->tail->prev) {
      KASSERT(lst->tail->prev->next == lst->tail);
    }
    kthread_queue_insert(lst->tail, thread);
    lst->tail = thread;
  }
  thread->queue = lst;
}

// Pop a thread off the front of a list.
kthread_t kthread_queue_pop(kthread_queue_t* lst) {
  if (!lst->head) {
    return lst->head;
  }
  kthread_data_t* front = lst->head;
  lst->head = front->next;
  if (front->next) {
    KASSERT(front->next->prev == front);
    front->next->prev = 0x0;
  } else {
    lst->tail = 0x0;
  }
  front->next = 0x0;
  KASSERT(front->next == 0x0 && front->prev == 0x0);
  KASSERT(front->queue == lst);
  front->queue = NULL;
  return front;
}

void kthread_queue_remove(kthread_t thread) {
  KASSERT_DBG(thread->queue != NULL);
  if (thread->queue->head == thread)
    thread->queue->head = thread->next;
  if (thread->queue->tail == thread)
    thread->queue->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  if (thread->next)
    thread->next->prev = thread->prev;
  thread->prev = thread->next = 0x0;
  thread->queue = NULL;
}

int kthread_queue_empty(kthread_queue_t* lst) {
  return lst->head == 0x0;
}

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
static void init_deadlock_data(kmutex_t* m) {
  // TODO(aoates): this could cause a false positive if we recreate mutexes
  // quickly enough (such that IDs are reused).
  m->id = fnv_hash_concat(fnv_hash_addr((addr_t)m), get_time_ms());
  m->link = LIST_LINK_INIT;
  for (int i = 0 ;i < KMUTEX_DEADLOCK_LRU_SIZE; ++i) {
    m->priors[i].id = 0;
    m->priors[i].lru = 0;
  }
}
#endif

void kmutex_init(kmutex_t* m) {
  m->locked = 0;
  m->holder = 0x0;
  kthread_queue_init(&m->wait_queue);

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  init_deadlock_data(m);
#endif

#if ENABLE_TSAN
  tsan_lock_init(&m->tsan);
#endif
}

void kmutex_lock(kmutex_t* m) {
  // We should never be blocking if we're holding a spinlock.
  KASSERT_DBG(kthread_current_thread()->spinlocks_held == 0);
  KASSERT_DBG(defint_running_state() == DEFINT_NONE);
  PUSH_AND_DISABLE_INTERRUPTS();
  if (m->locked) {
    // Mutexes are non-reentrant, so this would deadlock.
    KASSERT_MSG(m->holder != kthread_current_thread(),
                "Mutexs are non-reentrant: cannot lock mutex already held by "
                "the current thread!");
    scheduler_wait_on(&m->wait_queue);
    KASSERT(m->holder == kthread_current_thread());
  } else {
    m->locked = 1;
    m->holder = kthread_current_thread();
  }
  KASSERT(m->locked == 1);

#if ENABLE_TSAN
  tsan_acquire(&m->tsan, TSAN_LOCK);
#endif
  POP_INTERRUPTS();

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  if (m->id == 0) {
    init_deadlock_data(m);
  }
  apos_ms_t now = get_time_ms();
  int lru_search_start = 0;
  FOR_EACH_LIST(link_iter, &kthread_current_thread()->mutexes_held) {
    const kmutex_t* locked_mu = LIST_ENTRY(link_iter, kmutex_t, link);

    // Check if this mutex is in the locked mutex's priors.
    // TODO(aoates): if the LRU size needs to be increased, consider adding a
    // bloom filter here for the fast path.
    for (int i = 0; i < KMUTEX_DEADLOCK_LRU_SIZE; ++i) {
      if (locked_mu->priors[i].id == m->id) {
        klogfm(KL_PROC, FATAL,
               "Possible mutex deadlock detected.  Mutex A (%xu) locked while "
               "mutex B (%xu) held; previously B was locked while A was held\n",
               m->id, locked_mu->id);
      }
    }

    // Add the locked mutex to _this_ mutex's priors for future checks.
    int lru_idx = lru_search_start;
    apos_ms_t lru = m->priors[lru_idx].lru;
    for (int i_rel = 0; i_rel < KMUTEX_DEADLOCK_LRU_SIZE; ++i_rel) {
      const int i = (lru_search_start + i_rel) % KMUTEX_DEADLOCK_LRU_SIZE;
      if (m->priors[i].id == locked_mu->id || m->priors[i].id == 0) {
        // Already in the priors set, or an empty slot.  No need to continue.
        lru_idx = i;
        break;
      } else if (m->priors[i].lru < lru) {
        lru_idx = i;
        lru = m->priors[i].lru;
      }
    }
    m->priors[lru_idx].id = locked_mu->id;
    m->priors[lru_idx].lru = now;
    // Next time, start the LRU search right after the current index, to avoid
    // O(n^2) inserts for the common case.
    lru_search_start = (lru_idx + 1) % KMUTEX_DEADLOCK_LRU_SIZE;
  }

  list_push(&kthread_current_thread()->mutexes_held, &m->link);
#endif
}

static void kmutex_unlock_internal(kmutex_t* m, bool yield) {
#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  list_remove(&kthread_current_thread()->mutexes_held, &m->link);
#endif
  PUSH_AND_DISABLE_INTERRUPTS();

  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  if (!kthread_queue_empty(&m->wait_queue)) {
    // Try to find the first non-disabled waiter.
    kthread_t next_holder = m->wait_queue.head;
    while (next_holder && !next_holder->runnable) {
      next_holder = next_holder->next;
    }
    if (!next_holder) {
      next_holder = m->wait_queue.head;
    }
    kthread_queue_remove(next_holder);
    m->holder = next_holder;
    scheduler_make_runnable(next_holder);
    if (yield) scheduler_yield();
  } else {
    m->locked = 0;
    m->holder = 0x0;
  }
#if ENABLE_TSAN
  tsan_release(&m->tsan, TSAN_LOCK);
#endif
  POP_INTERRUPTS();
}

void kmutex_unlock(kmutex_t* m) {
  kmutex_unlock_internal(m, true);
}

void kmutex_unlock_no_yield(kmutex_t* m) {
  kmutex_unlock_internal(m, false);
}

bool kmutex_is_locked(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int is_locked = m->locked;
  POP_INTERRUPTS();
  return is_locked;
}

void kmutex_assert_is_held(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  POP_INTERRUPTS();
}

void kmutex_assert_is_not_held(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->holder != kthread_current_thread());
  POP_INTERRUPTS();
}
