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
#include "dev/interrupts.h"
#include "proc/defint_timer.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"

static void timer_cb(defint_timer_t* timer, void* arg) {
  process_t* proc = (process_t*)arg;
  kspin_lock(&proc->spin_mu);
  KASSERT_DBG(proc->state == PROC_RUNNING || proc->state == PROC_STOPPED);
  KASSERT_DBG(get_time_ms() >= proc->alarm.deadline_ms);

  proc->alarm.deadline_ms = APOS_MS_MAX;

  if (proc_force_signal_locked(proc, SIGALRM) != 0) {
    klogfm(KL_PROC, WARNING, "unable to send SIGALRM to pid %d\n", proc->id);
  }

  kspin_unlock(&proc->spin_mu);
  proc_put(proc);
}

void proc_alarm_init(proc_alarm_t* alarm) {
  alarm->deadline_ms = APOS_MS_MAX;
}

unsigned int proc_alarm_ms(unsigned int ms) {
  apos_ms_t ctime = get_time_ms();
  apos_ms_t deadline = ctime + ms;
  process_t* const proc = proc_current();

  kspin_lock(&proc->spin_mu);

  unsigned int old_remaining = 0;

  // If there's already an alarm, cancel it.
  if (proc->alarm.deadline_ms != APOS_MS_MAX) {
    // Note: add a grace period here because the defint could be running behind
    // schedule and miss a clock tick (unlikely, but possible).
    KASSERT_DBG(proc->alarm.deadline_ms + 10 >= ctime);
    old_remaining = round_nearest_div(proc->alarm.deadline_ms - ctime, 1000);
    old_remaining = max(old_remaining, 1U);

    proc_alarm_cancel(proc);
  }

  if (ms > 0) {
    proc->alarm.deadline_ms = deadline;
    refcount_inc(&proc->refcount);
    defint_timer_create(deadline, &timer_cb, proc, &proc->alarm.timer);
  }

  kspin_unlock(&proc->spin_mu);
  return old_remaining;
}

void proc_alarm_cancel(process_t* proc) {
  kspin_assert_is_held(&proc->spin_mu);

  if (proc->alarm.deadline_ms != APOS_MS_MAX) {
    if (defint_timer_cancel(&proc->alarm.timer)) {
      proc_put(proc);  // The (cancelled) timer's reference.
    }
    proc->alarm.deadline_ms = APOS_MS_MAX;
  }
}
