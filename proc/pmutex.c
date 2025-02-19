// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "proc/pmutex.h"

#include "common/kassert.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

void pmutex_init(pmutex_t* m) {
  kmutex_init(&m->_mu);
}

void pmutex_lock(pmutex_t* mu) NO_THREAD_SAFETY_ANALYSIS {
  sched_disable_preemption();
  kmutex_lock(&mu->_mu);
}

void pmutex_unlock(pmutex_t* mu) NO_THREAD_SAFETY_ANALYSIS {
  kmutex_unlock_no_yield(&mu->_mu);
  sched_restore_preemption();
}

bool pmutex_is_locked(const pmutex_t* m) {
  return kmutex_is_locked(&m->_mu);
}

void pmutex_assert_is_held(const pmutex_t* m) {
  KASSERT(kmutex_is_locked(&m->_mu));
}

void pmutex_assert_is_not_held(const pmutex_t* m) {
  KASSERT(!kmutex_is_locked(&m->_mu));
}
