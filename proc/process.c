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

#include "common/kassert.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/process-internal.h"
#include "proc/signal/signal.h"
#include "proc/user.h"

#define PROC_DEFAULT_UMASK 022

// We statically allocate the first process_t, so that proc_init() can run
// before kmalloc_init(), and therefore kmalloc_init() can set up its memory
// area.
static process_t g_first_process;

// vm_area_t's representing the regions mapped for the kernel binary, and the
// physically-mapped region, respectively.  They will be put in
// g_first_process's memory map.
static vm_area_t g_kernel_mapped_vm_area;
static vm_area_t g_physical_mapped_vm_area;

process_t* g_proc_table[PROC_MAX_PROCS];
static pid_t g_current_proc = -1;
static int g_proc_init_stage = 0;

static void proc_init_process(process_t* p) {
  p->id = -1;
  p->state = PROC_INVALID;
  p->thread = KTHREAD_NO_THREAD;
  p->exit_status = -0xABCD;
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    p->fds[i] = -1;
  }
  p->cwd = 0x0;
  p->vm_area_list = LIST_INIT;
  p->page_directory = 0;
  ksigemptyset(&p->pending_signals);
  proc_alarm_init(&p->alarm);
  for (int i = 0; i <= SIGMAX; ++i) {
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
  p->parent = 0x0;
  p->children_list = LIST_INIT;
  p->children_link = LIST_LINK_INIT;
  kthread_queue_init(&p->wait_queue);
}

process_t* proc_alloc() {
  int id = -1;
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    if (g_proc_table[i] == NULL && list_empty(proc_group_get(i))) {
      id = i;
      break;
    }
  }
  if (id < 0) return 0x0;

  process_t* proc = (process_t*)kmalloc(sizeof(process_t));
  if (!proc) return 0x0;

  proc_init_process(proc);
  proc->id = id;
  g_proc_table[id] = proc;
  return proc;
}

void proc_destroy(process_t* process) {
  KASSERT(process->state == PROC_INVALID);
  KASSERT(process->thread == KTHREAD_NO_THREAD);
  KASSERT(process->page_directory == 0x0);
  KASSERT(process->id > 0 && process->id < PROC_MAX_PROCS);
  KASSERT(g_proc_table[process->id] == process);

  g_proc_table[process->id] = NULL;
  process->id = -1;
  kfree(process);
}

void proc_init_stage1() {
  KASSERT(g_proc_init_stage == 0);
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    g_proc_table[i] = 0x0;
    *proc_group_get(i) = LIST_INIT;
  }

  // Create first process.
  g_proc_table[0] = &g_first_process;
  proc_init_process(g_proc_table[0]);
  g_proc_table[0]->id = 0;
  g_proc_table[0]->state = PROC_RUNNING;
  g_proc_table[0]->ruid = g_proc_table[0]->euid = g_proc_table[0]->suid =
      SUPERUSER_UID;
  g_proc_table[0]->rgid = g_proc_table[0]->egid = g_proc_table[0]->sgid =
      SUPERUSER_GID;
  g_proc_table[0]->pgroup = 0;
  list_push(proc_group_get(0), &g_proc_table[0]->pgroup_link);
  g_current_proc = 0;

  const memory_info_t* meminfo = get_global_meminfo();
  g_proc_table[0]->page_directory = meminfo->kernel_page_directory;

  g_proc_init_stage = 1;

  // Create vm_areas corresponding to the regions mapped in the loading code.
  // TODO(aoates): is there a better place to do this?
  vm_create_kernel_mapping(&g_kernel_mapped_vm_area, meminfo->mapped_start,
                           meminfo->mapped_end - meminfo->mapped_start,
                           false /* allow_allocation */);
  // Round up to the next MIN_GLOBAL_MAPPING_SIZE amount.
  const addr_t phys_map_len =
      ceiling_div(meminfo->phys_map_length, MIN_GLOBAL_MAPPING_SIZE) *
      MIN_GLOBAL_MAPPING_SIZE;
  vm_create_kernel_mapping(&g_physical_mapped_vm_area, meminfo->phys_map_start,
                           phys_map_len,
                           false /* allow_allocation */);
}

void proc_init_stage2() {
  KASSERT(g_proc_init_stage == 1);
  KASSERT(g_current_proc == 0);

  // Create first process.
  g_proc_table[0]->thread = kthread_current_thread();
  g_proc_table[0]->thread->process = g_proc_table[0];

  g_proc_init_stage = 2;
}

process_t* proc_current() {
  KASSERT(g_current_proc >= 0 && g_current_proc < PROC_MAX_PROCS);
  KASSERT(g_proc_init_stage >= 1);
  return g_proc_table[g_current_proc];
}

process_t* proc_get(pid_t id) {
  if (id < 0 || id >= PROC_MAX_PROCS)
    return NULL;
  else
    return g_proc_table[id];
}

void proc_set_current(process_t* process) {
  KASSERT_MSG(process->id >= 0 && process->id < PROC_MAX_PROCS,
              "bad process ID: %d", process->id);
  KASSERT(g_proc_table[process->id] == process);
  g_current_proc = process->id;
}
