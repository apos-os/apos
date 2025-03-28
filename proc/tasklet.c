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
#include "proc/tasklet.h"

#include "proc/defint.h"
#include "proc/spinlock.h"

static void tasklet_defint(void* arg) {
  tasklet_t* tl = (tasklet_t*)arg;
  kspin_lock_int(&tl->lock);
  tl->run = false;
  kspin_unlock_int(&tl->lock);
  tl->fn(tl, tl->arg);
}

void tasklet_init(tasklet_t* tl, tasklet_fn_t fn, void* arg) {
  tl->lock = KSPINLOCK_INTERRUPT_SAFE_INIT;
  tl->fn = fn;
  tl->arg = arg;
  tl->run = false;
}

bool tasklet_schedule(tasklet_t* tl) {
  bool result = false;
  kspin_lock_int(&tl->lock);
  if (!tl->run) {
    tl->run = true;
    defint_schedule(&tasklet_defint, tl);
    result = true;
  }
  kspin_unlock_int(&tl->lock);
  // Note: if this is called from a non-interrupt context, we won't run the
  // defint until the next interrupt or spinlock unlock.  That's OK.
  return result;
}
