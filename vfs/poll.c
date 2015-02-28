// Copyright 2015 Andrew Oates.  All Rights Reserved.
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
#include "vfs/poll.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/scheduler.h"

// Events that are always triggered, even if not requested by the caller.
#define ALWAYS_EVENTS (POLLHUP | POLLERR | POLLNVAL)

int poll_add_event(poll_state_t* poll, poll_event_t* event, short event_mask) {
  poll_ref_t* ref = kmalloc(sizeof(poll_ref_t));
  if (!ref) return -ENOMEM;

  ref->event_mask = event_mask;
  ref->poll = poll;
  ref->event = event;

  PUSH_AND_DISABLE_INTERRUPTS();
  list_push(&poll->refs, &ref->poll_link);
  list_push(&event->refs, &ref->event_link);
  POP_INTERRUPTS();
  return 0;
}

void poll_trigger_event(poll_event_t* event, short events) {
  PUSH_AND_DISABLE_INTERRUPTS();
  list_link_t* link = event->refs.head;
  while (link != NULL) {
    poll_ref_t* ref = container_of(link, poll_ref_t, event_link);
    KASSERT_DBG(ref->event == event);
    short masked_events = (ref->event_mask | ALWAYS_EVENTS) & events;
    if (masked_events) {
      ref->poll->triggered = true;
      scheduler_wake_one(&ref->poll->q);
      list_remove(&ref->poll->refs, &ref->poll_link);
      link = list_remove(&event->refs, link);
      kfree(ref);
    } else {
      link = link->next;
    }
  }
  POP_INTERRUPTS();
}

void poll_cancel(poll_state_t* poll) {
  PUSH_AND_DISABLE_INTERRUPTS();
  while (!list_empty(&poll->refs)) {
    list_link_t* link = list_pop(&poll->refs);
    poll_ref_t* ref = container_of(link, poll_ref_t, poll_link);
    KASSERT_DBG(ref->poll == poll);

    list_remove(&ref->event->refs, &ref->event_link);
    kfree(ref);
  }
  POP_INTERRUPTS();
}
