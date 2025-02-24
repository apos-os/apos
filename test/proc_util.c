// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "test/proc_util.h"

#include "common/kassert.h"
#include "common/list.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/pmutex.h"
#include "proc/process.h"

void proc_test_enable_threads(kpid_t pid) {
  process_t* proc = proc_get(pid);
  KASSERT(proc != NULL);

  pmutex_lock(&proc->mu);
  FOR_EACH_LIST(iter, &proc->threads) {
    kthread_t thread = LIST_ENTRY(iter, kthread_data_t, all_threads_link);
    kthread_enable(thread);
  }
  pmutex_unlock(&proc->mu);
}

void proc_test_disable_threads(kpid_t pid) {
  process_t* proc = proc_get(pid);
  KASSERT(proc != NULL);

  pmutex_lock(&proc->mu);
  FOR_EACH_LIST(iter, &proc->threads) {
    kthread_t thread = LIST_ENTRY(iter, kthread_data_t, all_threads_link);
    kthread_disable(thread);
  }
  pmutex_unlock(&proc->mu);
}
