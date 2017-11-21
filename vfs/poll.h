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

// Implementation of the poll() syscall, and helpers.  There are three poll
// components,
//  1) poll_state_t --- corresponds to a single poll() call.  Monitoring one  or
//     more poll_event_t's (one for each file descriptor).
//  2) poll_event_t --- an event to be polled for (generally corresponds to a
//     file descriptor).  May have multiple poll_state_t's waiting for it to
//     trigger.  Generally embedded in an underlying pollable-file impl.
//  3) poll_ref_t --- the glue between a poll_state_t and a poll_event_t that
//     it is waiting on.
//
// In other words, there is a many-to-many relationship between poll_state_t's
// and poll_event_t's.
#ifndef APOO_VFS_POLL_H
#define APOO_VFS_POLL_H

#include <stdbool.h>

#include "common/list.h"
#include "proc/kthread.h"
#include "user/include/apos/vfs/poll.h"

// The state of a single poll() call.
typedef struct {
  // Thread queue for the poll()'ing thread to wait on.
  kthread_queue_t q;

  // Set when the poll is triggered by an event.
  bool triggered;

  // The current set of poll_ref_t's.
  list_t refs;
} poll_state_t;

// An event that can be polled.  Generally corresponds (and is embedded in) a
// file, FIFO, etc.
typedef struct {
  list_t refs;
} poll_event_t;

// A hook between a poll_state_t and a poll_event_t that it is waiting on.
typedef struct {
  short event_mask;
  poll_state_t* poll;
  poll_event_t* event;
  list_link_t poll_link;
  list_link_t event_link;
} poll_ref_t;

void poll_init_event(poll_event_t* event);

// Add the given event to the poll (presumably to be triggered later).
int poll_add_event(poll_state_t* poll, poll_event_t* event, short event_mask);

// Trigger the given event, triggering each poll that is waiting on it whose
// event mask contains the event(s) in question.  Passing POLLNVAL indicates
// that the resource owning the poll_event_t is going away, and the event must
// not be referenced again.
//
// May be called from interrupts.
void poll_trigger_event(poll_event_t* event, short events);

// Cancel all the poll_ref_t's that are outstanding on the given poll.
void poll_cancel(poll_state_t* poll);

// Perform a poll, as per the poll() syscall.
int vfs_poll(struct pollfd fds[], nfds_t nfds, int timeout);

#endif
