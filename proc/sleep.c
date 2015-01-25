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

#include "common/kassert.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"

static void ksleep_cb(void* arg) {
  kthread_queue_t* q = (kthread_queue_t*)arg;
  scheduler_wake_one(q);
  KASSERT(kthread_queue_empty(q));
  kfree(q);
}

int ksleep(int ms) {
  // This isn't the most efficient way of doing things, but meh.
  kthread_queue_t* q = (kthread_queue_t*)kmalloc(sizeof(kthread_queue_t));
  kthread_queue_init(q);

  PUSH_AND_DISABLE_INTERRUPTS();
  const uint32_t start_time = get_time_ms();
  int result = register_event_timer(start_time + ms, &ksleep_cb, q, 0x0);
  if (result < 0) {
    kfree(q);
    POP_INTERRUPTS();
    return result;
  }
  int wait_result = scheduler_wait_on_interruptable(q);
  const uint32_t elapsed = get_time_ms() - start_time;
  result = (wait_result == SWAIT_INTERRUPTED) ? max((ms - elapsed), 0U) : 0;
  POP_INTERRUPTS();
  return result;
}
