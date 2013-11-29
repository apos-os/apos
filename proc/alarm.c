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
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/process.h"
#include "proc/signal/signal.h"

// Sorted list of alarms, in order of when they expire.
static list_t g_alarm_list = LIST_INIT_STATIC;

static void timer_cb(void* arg) {
  const uint32_t ctime = get_time_ms();

  // Send SIGALRM to any expired alarms.
  while (!list_empty(&g_alarm_list)) {
    proc_alarm_t* alarm = container_of(g_alarm_list.head, proc_alarm_t, link);
    if (alarm->deadline_ms > ctime) break;

    list_pop(&g_alarm_list);
    process_t* proc = container_of(alarm, process_t, alarm);
    proc->alarm.deadline_ms = 0;
    if (proc_kill(proc->id, SIGALRM) != 0) {
      klogf("WARNING: unable to send SIGALRM to pid %d\n", proc->id);
    }
  }

  // If we still have any outstanding alarms, schedule a new timer to fire.
  // TODO(aoates): this isn't a great system --- we could end up with an
  // unbounded number of outstanding timers, which is bad because they're a
  // (very) limited resource.
  if (!list_empty(&g_alarm_list)) {
    proc_alarm_t* alarm = container_of(g_alarm_list.head, proc_alarm_t, link);
    uint32_t len = alarm->deadline_ms - ctime;
    KASSERT_DBG(len > 0);
    KASSERT(register_timer_callback(len, 1, &timer_cb, 0x0) == 0);
  }
}

void proc_alarm_init(proc_alarm_t* alarm) {
  alarm->deadline_ms = 0;
  alarm->link = LIST_LINK_INIT;
}

unsigned int proc_alarm(unsigned int seconds) {
  uint32_t ctime = get_time_ms();
  uint32_t deadline = ctime + seconds * 1000;
  process_t* const proc = proc_current();

  PUSH_AND_DISABLE_INTERRUPTS();

  unsigned int old_remaining = 0;

  // If there's already an alarm, cancel it.
  if (proc->alarm.deadline_ms > 0) {
    KASSERT_DBG(proc->alarm.deadline_ms >= ctime);
    list_remove(&g_alarm_list, &proc->alarm.link);
    old_remaining = (proc->alarm.deadline_ms - ctime) / 1000;
    proc->alarm.deadline_ms = 0;
  }

  if (seconds > 0) {
    proc->alarm.deadline_ms = deadline;

    // Insert the alarm in its spot in the priority queue.
    list_link_t* prev = 0x0;
    for (list_link_t* link = g_alarm_list.head; link != 0x0;
         link = link->next) {
      proc_alarm_t* alarm = container_of(link, proc_alarm_t, link);
      if (alarm->deadline_ms >= proc->alarm.deadline_ms) break;
      prev = link;
    }

    list_insert(&g_alarm_list, prev, &proc->alarm.link);

    // Register a new timer callback if necessary.
    if (prev == 0x0) {
      KASSERT(
          register_timer_callback(deadline - ctime, 1, &timer_cb, 0x0) == 0);
    }
  }

  POP_INTERRUPTS();
  return old_remaining;
}
