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

#include "common/kassert.h"
#include "common/list.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"

typedef struct {
  defint_func_t f;
  void* arg;
  list_link_t link;
} defint_data_t;

static list_t g_queued_defints = LIST_INIT_STATIC;
static bool g_defints_enabled = true;

void defint_schedule(void (*f)(void*), void* arg) {
  defint_data_t* defint = (defint_data_t*)kmalloc(sizeof(defint_data_t));
  KASSERT(defint);
  defint->f = f;
  defint->arg = arg;
  defint->link = LIST_LINK_INIT;

  PUSH_AND_DISABLE_INTERRUPTS();
  list_push(&g_queued_defints, &defint->link);
  POP_INTERRUPTS();
}

defint_state_t defint_state() {
  PUSH_AND_DISABLE_INTERRUPTS();
  defint_state_t result = g_defints_enabled;
  POP_INTERRUPTS();
  return result;
}

defint_state_t defint_set_state(defint_state_t s) {
  PUSH_AND_DISABLE_INTERRUPTS();
  bool old = g_defints_enabled;
  if (s) {
    g_defints_enabled = true;
    defint_process_queued();
  } else {
    g_defints_enabled = false;
  }
  POP_INTERRUPTS();
  return old;
}

void defint_process_queued() {
  KASSERT(!interrupts_enabled());
  if (!g_defints_enabled) return;

  // Prevent any new defints from being processed while we're working.
  g_defints_enabled = false;

  // TODO(aoates): consider capping the number of defints we run at a given time
  // to minimize impact on the thread we're victimizing.
  while (!list_empty(&g_queued_defints)) {
    list_link_t* link = list_pop(&g_queued_defints);
    enable_interrupts();

    defint_data_t* data = container_of(link, defint_data_t, link);
    data->f(data->arg);
    kfree(data);

    disable_interrupts();
  }
  g_defints_enabled = true;
}

void _defint_disabled_die() {
  die("Leaving code block without reenabling defints");
}
