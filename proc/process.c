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
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"

static process_t* g_proc_table[PROC_MAX_PROCS];
static int g_current_proc = -1;

static void proc_init_process(process_t* p) {
  p->id = -1;
  p->thread = 0x0;
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    p->fds[i] = -1;
  }
  p->cwd = 0x0;
}

void proc_init() {
  for (int i = 0; i < PROC_MAX_PROCS; ++i) {
    g_proc_table[i] = 0x0;
  }

  // Create first process.
  g_proc_table[0] = (process_t*)kmalloc(sizeof(process_t));
  proc_init_process(g_proc_table[0]);
  g_proc_table[0]->id = 0;
  g_proc_table[0]->thread = kthread_current_thread();
  g_proc_table[0]->thread->process = g_proc_table[0];
  g_proc_table[0]->vm_area_list = LIST_INIT;
  g_current_proc = 0;
}

process_t* proc_current() {
  KASSERT(g_current_proc >= 0 && g_current_proc < PROC_MAX_PROCS);
  return g_proc_table[g_current_proc];
}
