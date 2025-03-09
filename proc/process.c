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

#include <stddef.h>
#include <stdint.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "common/math.h"
#include "common/refcount.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/exit.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/load/load.h"
#include "proc/process.h"
#include "proc/pmutex.h"
#include "proc/process-internal.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "proc/user.h"

#define PROC_DEFAULT_UMASK 022

atomic_flag_t g_forked = ATOMIC_FLAG_INIT;

// We statically allocate the first process_t, so that proc_init() can run
// before kmalloc_init(), and therefore kmalloc_init() can set up its memory
// area.
static process_t g_first_process;

// Global lock that protects the process table, process groups, and sessions.
kspinlock_t g_proc_table_lock = KSPINLOCK_NORMAL_INIT_STATIC;

// vm_area_t's representing the regions mapped for the kernel binary, and the
// physically-mapped region, respectively.  They will be put in
// g_first_process's memory map.
static vm_area_t g_kernel_mapped_vm_area;
static vm_area_t g_physical_mapped_vm_area[MEM_MAX_PHYS_MAPS];

process_t* g_proc_table[PROC_MAX_PROCS] GUARDED_BY(g_proc_table_lock);
static kpid_t g_current_proc = -1;
static int g_proc_init_stage = 0;
static uint32_t g_next_guid GUARDED_BY(g_proc_table_lock) = 1;

proc_state_t proc_state(kpid_t pid) {
  process_t* p = proc_get_ref(pid);
  if (!p) {
    return PROC_INVALID;
  }
  kspin_lock(&p->spin_mu);
  proc_state_t state = p->state;
  kspin_unlock(&p->spin_mu);
  proc_put(p);
  return state;
}

static void proc_init_process(process_t* p) NO_THREAD_SAFETY_ANALYSIS {
  pmutex_init(&p->mu);
  p->spin_mu = KSPINLOCK_NORMAL_INIT;
  p->refcount = REFCOUNT_INIT;
  p->guid = 0;
  p->id = -1;
  p->state = PROC_INVALID;
  p->threads = LIST_INIT;
  p->exit_status = 0;
  p->exiting = false;
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    p->fds[i].file = -1;
    p->fds[i].flags = 0;
  }
  p->cwd = 0x0;
  p->vm_area_list = LIST_INIT;
  p->page_directory = 0;
  ksigemptyset(&p->pending_signals);
  proc_alarm_init(&p->alarm);
  for (int i = 0; i <= APOS_SIGMAX; ++i) {
    ksigemptyset(&p->signal_dispositions[i].sa_mask);
    p->signal_dispositions[i].sa_flags = 0;
    p->signal_dispositions[i].sa_handler = SIG_DFL;
  }
  p->ruid = p->euid = p->suid = -1;
  p->rgid = p->egid = p->sgid = -1;
  p->pgroup = -1;
  p->pgroup_link = LIST_LINK_INIT;
  p->umask = PROC_DEFAULT_UMASK;
  p->execed = false;
  p->user_arch = BIN_NONE;
  p->parent = 0x0;
  p->children_list = LIST_INIT;
  p->children_link = LIST_LINK_INIT;
  kthread_queue_init(&p->wait_queue);
  kthread_queue_init(&p->stopped_queue);
  kthread_queue_init(&p->thread_change_queue);

  for (int i = 0; i < APOS_RLIMIT_NUM_RESOURCES; ++i) {
    p->limits[i].rlim_cur = APOS_RLIM_INFINITY;
    p->limits[i].rlim_max = APOS_RLIM_INFINITY;
  }
}

process_t* proc_alloc(void) {
  process_t* proc = (process_t*)kmalloc(sizeof(process_t));
  if (!proc) return 0x0;
  proc_init_process(proc);

  int id = -1;
  kspin_lock(&g_proc_table_lock);
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    if (g_proc_table[i] == NULL && list_empty(&proc_group_get(i)->procs)) {
      id = i;
      break;
    }
  }
  if (id < 0) {
    kspin_unlock(&g_proc_table_lock);
    kfree(proc);
    return 0x0;
  }
  proc->guid = g_next_guid++;
  proc->id = id;
  g_proc_table[id] = proc;
  kspin_unlock(&g_proc_table_lock);
  return proc;
}

void proc_destroy(process_t* process) {
  kspin_lock(&process->spin_mu);
  KASSERT(refcount_get(&process->refcount) == 0);
  KASSERT(process->state == PROC_INVALID);
  KASSERT(list_empty(&process->threads));
  KASSERT(process->page_directory == 0x0);
  KASSERT(process->id > 0 && process->id < PROC_MAX_PROCS);
  kspin_unlock(&process->spin_mu);

  kspin_lock(&g_proc_table_lock);
  KASSERT(g_proc_table[process->id] == process);
  g_proc_table[process->id] = NULL;
  kspin_unlock(&g_proc_table_lock);

  process->id = -1;
  kfree(process);
}

void proc_init_stage1(void) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(g_proc_init_stage == 0);
  kspin_constructor(&g_proc_table_lock);
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    g_proc_table[i] = 0x0;

    proc_group_t* pgroup = proc_group_get(i);
    pgroup->num_procs = 0;
    pgroup->procs = LIST_INIT;
    pgroup->session = -1;

    proc_session_t* session = proc_session_get(i);
    session->ctty = -100;
    session->fggrp = -100;
  }

  // Create first process.
  g_proc_table[0] = &g_first_process;
  proc_init_process(g_proc_table[0]);
  g_proc_table[0]->guid = g_next_guid++;
  g_proc_table[0]->id = 0;
  g_proc_table[0]->state = PROC_RUNNING;
  g_proc_table[0]->ruid = g_proc_table[0]->euid = g_proc_table[0]->suid =
      SUPERUSER_UID;
  g_proc_table[0]->rgid = g_proc_table[0]->egid = g_proc_table[0]->sgid =
      SUPERUSER_GID;
  g_proc_table[0]->pgroup = 0;
  proc_group_add(proc_group_get(0), g_proc_table[0]);
  proc_group_get(0)->session = 0;
  g_current_proc = 0;

  const memory_info_t* meminfo = get_global_meminfo();
  g_proc_table[0]->page_directory = meminfo->kernel_page_directory;

  g_proc_init_stage = 1;

  // Create vm_areas corresponding to the regions mapped in the loading code.
  // TODO(aoates): is there a better place to do this?
  vm_create_kernel_mapping(
      &g_kernel_mapped_vm_area, meminfo->kernel_mapped.base,
      meminfo->kernel_mapped.len, false /* allow_allocation */);
  for (int i = 0; i < MEM_MAX_PHYS_MAPS; ++i) {
    if (meminfo->phys_maps[i].phys.len == 0) continue;

    // Round up to the next MIN_GLOBAL_MAPPING_SIZE amount.
    const addr_t phys_map_len =
        ceiling_div(meminfo->phys_maps[i].phys.len, MIN_GLOBAL_MAPPING_SIZE) *
        MIN_GLOBAL_MAPPING_SIZE;
    vm_create_kernel_mapping(&g_physical_mapped_vm_area[i],
                             meminfo->phys_maps[i].virt_base, phys_map_len,
                             false /* allow_allocation */);
  }
}

void proc_init_stage2(void) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(g_proc_init_stage == 1);
  KASSERT(g_current_proc == 0);

  // Create first process.
  list_push(&g_proc_table[0]->threads,
            &kthread_current_thread()->proc_threads_link);
  kthread_current_thread()->process = g_proc_table[0];

  g_proc_init_stage = 2;
}

process_t* proc_current(void) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(g_current_proc >= 0 && g_current_proc < PROC_MAX_PROCS);
  KASSERT(g_proc_init_stage >= 1);
  // TODO(aoates): consider a check here to verify raw kernel threads don't
  // reference process data (such as file descriptors).
  // No need to lock the table lock, we know our reference is good.
  return g_proc_table[g_current_proc];
}

process_t* proc_get(kpid_t id) {
  process_t* proc = proc_get_ref(id);
  if (proc) {
    KASSERT(refcount_get(&proc->refcount) > 1);
    proc_put(proc);
  }
  return proc;
}

process_t* proc_get_locked(kpid_t id) {
  if (id < 0 || id >= PROC_MAX_PROCS) {
    return NULL;
  } else {
    return g_proc_table[id];
  }
}

process_t* proc_get_ref(kpid_t id) {
  if (id < 0 || id >= PROC_MAX_PROCS) {
    return NULL;
  } else {
    kspin_lock(&g_proc_table_lock);
    process_t* p = g_proc_table[id];
    if (p) {
      refcount_inc(&p->refcount);
    }
    kspin_unlock(&g_proc_table_lock);
    return p;
  }
}

void proc_put(process_t* proc) {
  if (refcount_dec(&proc->refcount) == 0) {
    proc_destroy(proc);
  }
}

void proc_set_current(process_t* process) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT_MSG(process->id >= 0 && process->id < PROC_MAX_PROCS,
              "bad process ID: %d", process->id);
  // No need to lock the table lock, there is no data race so long as the
  // process table is valid.
  KASSERT(g_proc_table[process->id] == process);
  g_current_proc = process->id;
}

typedef struct {
  void* (*start_routine)(void*);
  void* arg;
} proc_thread_tramp_args_t;

// TODO(aoates): seems a bit silly to have a dedicated trampoline for this (in
// addition to the standard kthread trampoline, which calls this); is there a
// way to avoid it?
// Trampolines to the start routine, calling proc_thread_exit() after rather
// than kthread_exit().
static void* proc_thread_trampoline(void* arg) {
  proc_thread_tramp_args_t args = *(proc_thread_tramp_args_t*)arg;
  kfree(arg);

  proc_thread_exit(args.start_routine(args.arg));
  die("unreachable");
}

int proc_thread_create(kthread_t* thread, void* (*start_routine)(void*),
                       void* arg) {
  process_t* const proc = proc_current();
  kspin_lock(&proc->spin_mu);
  if (proc_current()->exiting) {
    kspin_unlock(&proc->spin_mu);
    return -EINTR;
  }

  proc_thread_tramp_args_t* pt_args =
      (proc_thread_tramp_args_t*)kmalloc(sizeof(proc_thread_tramp_args_t));
  pt_args->start_routine = start_routine;
  pt_args->arg = arg;
  int result = kthread_create(thread, &proc_thread_trampoline, pt_args);
  if (result) {
    kspin_unlock(&proc->spin_mu);
    kfree(pt_args);
    return result;
  }

  (*thread)->process = proc;
  list_push(&proc->threads, &(*thread)->proc_threads_link);
  scheduler_wake_all(&proc->thread_change_queue);
  kspin_unlock(&proc->spin_mu);

  scheduler_make_runnable(*thread);
  return 0;
}

void proc_thread_exit(void* x) {
  process_t* const p = proc_current();
  kthread_t thread = kthread_current_thread();
  KASSERT(thread->process == p);
  kspin_lock(&p->spin_mu);
  KASSERT_DBG(list_link_on_list(&p->threads, &thread->proc_threads_link));
  KASSERT(p->state == PROC_RUNNING || p->state == PROC_STOPPED);

  list_remove(&p->threads, &thread->proc_threads_link);
  scheduler_wake_all(&p->thread_change_queue);
  thread->process = NULL;
  bool last_thread = list_empty(&p->threads);
  kspin_unlock(&p->spin_mu);

  // If we're the last thread left in the process, exit the process.
  if (last_thread) {
    proc_finish_exit();
    die("unreachable");
  }

  // Someone else will clean up.
  kthread_exit(x);
  die("unreachable");
}

process_t* proc_get_and_lock_parent(process_t* child)
    NO_THREAD_SAFETY_ANALYSIS {
  // We must always lock in parent->child order --- however, the process's
  // parent can change.  The process hierarchy is guaranteed to be a DAG
  // (unless, say, vnodes), so we have a simpler retry loop.
  //
  // In practice processes are only every reparented to the root node, but this
  // logic is general.
  while (true) {
    // First read the parent.
    pmutex_lock(&child->mu);
    process_t* parent = child->parent;
    refcount_inc(&parent->refcount);
    pmutex_unlock(&child->mu);

    // We have a refcount on the parent, so now we can relock in order.
    pmutex_lock(&parent->mu);
    pmutex_lock(&child->mu);
    if (child->parent == parent) {
      return parent;
    }
    KASSERT(child->parent->id == 0);  // Should only be reparented to root proc.
    pmutex_unlock(&child->mu);
    pmutex_unlock(&parent->mu);
  }
  die("unreachable");
}
