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
#include "dev/dev.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/scheduler.h"
#include "vfs/vfs_internal.h"

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

// Helper for vfs_poll().  Performs a poll() on a single file descriptor.
// Returns the set of pending events (>0) if there are any pending, 0 if there
// aren't any events currently, and < 0 on error.
//
// If state is non-NULL, and there are no pending events, sets up a delayed
// trigger on the given fd.
static int vfs_poll_fd(int fd, short event_mask, poll_state_t* poll) {
  file_t* file = NULL;
  int result = lookup_fd(fd, &file);
  if (result == -EBADF) return 0;

  switch (file->vnode->type) {
    case VNODE_REGULAR:
      return (POLLIN | POLLOUT) & event_mask;

    case VNODE_DIRECTORY:
      if (event_mask & ~ALWAYS_EVENTS)
        return POLLNVAL;
      else
        return 0;

    case VNODE_CHARDEV: {
      char_dev_t* chardev = dev_get_char(file->vnode->dev);
      if (!chardev) return 0;
      return chardev->poll(chardev, event_mask, poll);
    }

    case VNODE_BLOCKDEV:
    case VNODE_FIFO:
      // TODO(aoates): implement
      break;

    case VNODE_SYMLINK:
    case VNODE_INVALID:
    case VNODE_UNINITIALIZED:
      die("invalid or unitialized vnode");
  }
  return 0;
}

int vfs_poll(struct pollfd fds[], nfds_t nfds, int timeout_ms) {
  int result = 0;
  poll_state_t poll;
  kthread_queue_init(&poll.q);
  poll.triggered = false;
  poll.refs = LIST_INIT;

  // TODO(aoates): test nfds against OPEN_MAX.
  for (size_t i = 0; i < nfds; ++i) fds[i].revents = 0;

  int fds_selected = 0;
  uint32_t end_time = get_time_ms() + timeout_ms;
  poll_state_t* poll_ptr = (timeout_ms == 0) ? NULL : &poll;
  do {
    poll_cancel(&poll);
    for (size_t i = 0; i < nfds; ++i) {
      result = vfs_poll_fd(fds[i].fd, fds[i].events, poll_ptr);
      if (result < 0) break;
      if (result > 0) {
        fds[i].revents = result;
        fds_selected++;
        poll_ptr = NULL;  // No need to set up polls for other fds.
      }
    }

    if (fds_selected > 0) {
      result = fds_selected;
      break;
    }

    uint32_t now = get_time_ms();
    if (timeout_ms != 0 && now < end_time) {
      // TODO(aoates): atomically test poll.triggered
      result = scheduler_wait_on_interruptable(&poll.q, timeout_ms);
      if (result == SWAIT_INTERRUPTED) {
        result = -EINTR;
        break;
      } else if (result == SWAIT_TIMEOUT) {
        result = 0;
        break;
      }
    }
  } while (fds_selected == 0 && timeout_ms != 0);
  poll_cancel(&poll);

  if (result == 0) result = fds_selected;

  return result;
}
