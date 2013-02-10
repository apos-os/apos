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
#include "dev/timer.h"
#include "kmalloc.h"
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

  int result = register_timer_callback(ms, 1, &ksleep_cb, q);
  if (result < 0) {
    kfree(q);
    return result;
  }
  kthread_queue_init(q);
  scheduler_wait_on(q);
  return 0;
}
