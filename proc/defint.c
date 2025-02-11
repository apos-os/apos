// Copyright 2019 Andrew Oates.  All Rights Reserved.
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

#include "proc/defint.h"

#include "common/attributes.h"
#include "common/kassert.h"
#include "common/list.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

#define MAX_QUEUED_DEFINTS 100

typedef struct {
  defint_func_t f;
  void* arg;
} defint_data_t;

static defint_data_t g_defint_queue[MAX_QUEUED_DEFINTS];
static int g_queue_start = 0;
static int g_queue_len = 0;
static bool g_defints_enabled = false;
static defint_running_t g_defint_running = DEFINT_NONE;

void defint_schedule(void (*f)(void*), void* arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(g_queue_len < MAX_QUEUED_DEFINTS);
  int idx = (g_queue_start + g_queue_len) % MAX_QUEUED_DEFINTS;
  KASSERT_DBG(g_defint_queue[idx].f == NULL);
  defint_data_t* defint = &g_defint_queue[idx];
  defint->f = f;
  defint->arg = arg;
  g_queue_len++;
#if ENABLE_TSAN
  // Release all this thread's values to the defint as an explicit sync point.
  tsan_release(NULL, TSAN_DEFINTS);
#endif
  POP_INTERRUPTS();
}

defint_state_t defint_state(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  defint_state_t result = g_defints_enabled;
  POP_INTERRUPTS();
  return result;
}

defint_state_t defint_set_state(defint_state_t s) {
#if ENABLE_TSAN
  if (s) {
    tsan_release(NULL, TSAN_DEFINTS);
  }
#endif
  PUSH_AND_DISABLE_INTERRUPTS();
  bool old = g_defints_enabled;
  g_defints_enabled = s;
  POP_INTERRUPTS();
  if (s) {
    defint_process_queued(/* force= */ false);
#if ENABLE_TSAN
  } else {
    tsan_acquire(NULL, TSAN_DEFINTS);
#endif
  }
  return old;
}

void defint_process_queued(bool force) {
  if (!interrupts_enabled() && !force) {
    return;
  }
  PUSH_AND_DISABLE_INTERRUPTS();
  if (!g_defints_enabled) {
    POP_INTERRUPTS();
    return;
  }
  KASSERT_DBG(g_defint_running == DEFINT_NONE);

  sched_disable_preemption();

  // Prevent any new defints from being processed while we're working.
  g_defints_enabled = false;
  g_defint_running = (kthread_current_thread()->interrupt_level == 0)
                         ? DEFINT_THREAD_CTX
                         : DEFINT_INTERRUPT_CTX;

  // TODO(aoates): consider capping the number of defints we run at a given time
  // to minimize impact on the thread we're victimizing.
  while (g_queue_len > 0) {
    defint_data_t* data = &g_defint_queue[g_queue_start];

    enable_interrupts();
    data->f(data->arg);
    disable_interrupts();

    data->f = NULL;
    g_queue_start = (g_queue_start + 1) % MAX_QUEUED_DEFINTS;
    g_queue_len--;
  }
  g_defint_running = DEFINT_NONE;
  g_defints_enabled = true;

  // TODO(aoates): if we would have preempted the process during the defint, do
  // so now (in the scheduler).
  sched_restore_preemption();
  POP_INTERRUPTS();
}

void _defint_disabled_die(void) {
  die("Leaving code block without reenabling defints");
}

NO_SANITIZER
defint_running_t defint_running_state(void) {
  return g_defint_running;
}
