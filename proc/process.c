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

#include "common/kassert.h"
#include "common/math.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"

// We statically allocate the first process_t, so that proc_init() can run
// before kmalloc_init(), and therefore kmalloc_init() can set up its memory
// area.
static process_t g_first_process;

// vm_area_t's representing the regions mapped for the kernel binary, and the
// physically-mapped region, respectively.  They will be put in
// g_first_process's memory map.
static vm_area_t g_kernel_mapped_vm_area;
static vm_area_t g_physical_mapped_vm_area;

static process_t* g_proc_table[PROC_MAX_PROCS];
static int g_current_proc = -1;
static int g_proc_init_stage = 0;

static void proc_init_process(process_t* p) {
  p->id = -1;
  p->thread = KTHREAD_NO_THREAD;
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    p->fds[i] = -1;
  }
  p->cwd = 0x0;
  p->vm_area_list = LIST_INIT;
  p->page_directory = 0;
}

void proc_init_stage1() {
  KASSERT(g_proc_init_stage == 0);
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    g_proc_table[i] = 0x0;
  }

  // Create first process.
  g_proc_table[0] = &g_first_process;
  proc_init_process(g_proc_table[0]);
  g_proc_table[0]->id = 0;
  g_current_proc = 0;

  const memory_info_t* meminfo = get_global_meminfo();
  g_proc_table[0]->page_directory = meminfo->kernel_page_directory;

  g_proc_init_stage = 1;

  // Create vm_areas corresponding to the regions mapped in the loading code.
  // TODO(aoates): is there a better place to do this?
  vm_create_kernel_mapping(&g_kernel_mapped_vm_area, meminfo->mapped_start,
                           meminfo->mapped_end - meminfo->mapped_start,
                           0 /* allow_allocation */);
  // Round up to the next MIN_GLOBAL_MAPPING_SIZE amount.
  const addr_t phys_map_len =
      ceiling_div(meminfo->phys_map_length, MIN_GLOBAL_MAPPING_SIZE) *
      MIN_GLOBAL_MAPPING_SIZE;
  vm_create_kernel_mapping(&g_physical_mapped_vm_area, meminfo->phys_map_start,
                           phys_map_len,
                           0 /* allow_allocation */);
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
