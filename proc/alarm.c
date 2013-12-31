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

#include "proc/alarm.h"

#include "common/kassert.h"
#include "common/math.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/process.h"
#include "proc/signal/signal.h"

static void timer_cb(void* arg) {
  process_t* proc = (process_t*)arg;
  KASSERT_DBG(proc->state == PROC_RUNNING);
  KASSERT_DBG(get_time_ms() >= proc->alarm.deadline_ms);

  proc->alarm.timer = TIMER_HANDLE_NONE;
  proc->alarm.deadline_ms = 0;

  if (proc_force_signal(proc, SIGALRM) != 0) {
    klogfm(KL_PROC, WARNING, "unable to send SIGALRM to pid %d\n", proc->id);
  }
}

void proc_alarm_init(proc_alarm_t* alarm) {
  alarm->deadline_ms = 0;
  alarm->timer = TIMER_HANDLE_NONE;
}

unsigned int proc_alarm(unsigned int seconds) {
  uint32_t ctime = get_time_ms();
  uint32_t deadline = ctime + seconds * 1000;
  process_t* const proc = proc_current();

  PUSH_AND_DISABLE_INTERRUPTS();

  unsigned int old_remaining = 0;

  // If there's already an alarm, cancel it.
  if (proc->alarm.timer != TIMER_HANDLE_NONE) {
    KASSERT_DBG(proc->alarm.deadline_ms >= ctime);
    old_remaining = round_nearest_div(proc->alarm.deadline_ms - ctime, 1000);
    old_remaining = max(old_remaining, 1U);

    cancel_event_timer(proc->alarm.timer);
    proc->alarm.timer = TIMER_HANDLE_NONE;
    proc->alarm.deadline_ms = 0;
  }

  if (seconds > 0) {
    proc->alarm.deadline_ms = deadline;

    if (register_event_timer(deadline, &timer_cb, proc,
                             &proc->alarm.timer) != 0) {
      klogfm(KL_PROC, WARNING,
             "unable to register alarm for pid %d\n", proc->id);
    }
  }

  POP_INTERRUPTS();
  return old_remaining;
}
