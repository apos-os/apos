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
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "vfs/vfs_internal.h"

// Events that are always triggered, even if not requested by the caller.
#define ALWAYS_EVENTS (KPOLLHUP | KPOLLERR | KPOLLNVAL)

// Cancel all the poll_ref_t's that are outstanding on the given poll.
void poll_cancel(poll_state_t* poll);

// A hook between a poll_state_t and a poll_event_t that it is waiting on.
typedef struct {
  short event_mask;
  poll_state_t* poll;
  pollable_t* event;
  list_link_t poll_link;
  list_link_t event_link;
} poll_ref_t;

// TODO(aoates): move to more fine-grained locking.
kspinlock_t g_poll_lock = KSPINLOCK_NORMAL_INIT_STATIC;

void poll_init_event(pollable_t* event) {
  kspin_constructor(&g_poll_lock);
  event->refs = LIST_INIT;
}

int poll_add_event(poll_state_t* poll, pollable_t* event, short event_mask) {
  KASSERT_DBG(poll != NULL);
  poll_ref_t* ref = kmalloc(sizeof(poll_ref_t));
  if (!ref) return -ENOMEM;

  ref->event_mask = event_mask;
  ref->poll = poll;
  ref->event = event;
  ref->event_link = LIST_LINK_INIT;
  ref->poll_link = LIST_LINK_INIT;

  kspin_lock(&g_poll_lock);
  list_push(&poll->refs, &ref->poll_link);
  list_push(&event->refs, &ref->event_link);
  kspin_unlock(&g_poll_lock);
  return 0;
}

void poll_trigger_event(pollable_t* event, short events) {
  KASSERT_DBG(kthread_execution_context() != KTCTX_INTERRUPT);
  kspin_lock(&g_poll_lock);
  list_link_t* link = event->refs.head;
  while (link != NULL) {
    poll_ref_t* ref = container_of(link, poll_ref_t, event_link);
    KASSERT_DBG(ref->event == event);
    KASSERT_DBG((ref->event_mask & ALWAYS_EVENTS) == ALWAYS_EVENTS);
    short masked_events = ref->event_mask & events;
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
  kspin_unlock(&g_poll_lock);
}

void poll_cancel(poll_state_t* poll) {
  kspin_lock(&g_poll_lock);
  poll->triggered = false;
  while (!list_empty(&poll->refs)) {
    list_link_t* link = list_pop(&poll->refs);
    poll_ref_t* ref = container_of(link, poll_ref_t, poll_link);
    KASSERT_DBG(ref->poll == poll);

    list_remove(&ref->event->refs, &ref->event_link);
    kfree(ref);
  }
  kspin_unlock(&g_poll_lock);
}

// Helper for vfs_poll().  Performs a poll() on a single file descriptor.
// Returns the set of pending events (>0) if there are any pending, 0 if there
// aren't any events currently, and < 0 on error.
//
// If state is non-NULL, and there are no pending events, sets up a delayed
// trigger on the given fd.
static int vfs_poll_fd(int fd, short event_mask, poll_state_t* poll) {
  if (fd < 0) return 0;
  file_t* file = NULL;
  int result = lookup_fd(fd, &file);
  if (result == -EBADF) return KPOLLNVAL;

  kmode_t mode = file->mode;
  vnode_t* vnode = VFS_COPY_REF(file->vnode);
  file_unref(file);
  file = NULL;
  switch (vnode->type) {
    case VNODE_REGULAR:
      VFS_PUT_AND_CLEAR(vnode);
      return (KPOLLIN | KPOLLOUT) & event_mask;

    case VNODE_DIRECTORY:
      VFS_PUT_AND_CLEAR(vnode);
      if (event_mask & ~ALWAYS_EVENTS)
        return KPOLLNVAL;
      else
        return 0;

    case VNODE_CHARDEV: {
      char_dev_t* chardev = dev_get_char(vnode->dev);
      VFS_PUT_AND_CLEAR(vnode);
      if (!chardev) return KPOLLERR;
      return chardev->poll(chardev, event_mask | ALWAYS_EVENTS, poll);
    }

    case VNODE_FIFO:
      result = fifo_poll(vnode->fifo, mode, event_mask | ALWAYS_EVENTS, poll);
      VFS_PUT_AND_CLEAR(vnode);
      return result;

    case VNODE_SOCKET:
      result = vnode->socket->s_ops->poll(
          vnode->socket, event_mask | ALWAYS_EVENTS, poll);
      VFS_PUT_AND_CLEAR(vnode);
      return result;

    case VNODE_BLOCKDEV: {
      block_dev_t* blockdev = dev_get_block(vnode->dev);
      VFS_PUT_AND_CLEAR(vnode);
      if (!blockdev) return KPOLLERR;
      return (KPOLLIN | KPOLLOUT) & event_mask;
    }

    case VNODE_SYMLINK:
    case VNODE_INVALID:
    case VNODE_UNINITIALIZED:
    case VNODE_MAX:
      die("invalid or unitialized vnode");
  }
  return 0;
}

static void init_poll_state(poll_state_t* poll) {
  kspin_constructor(&g_poll_lock);
  kthread_queue_init(&poll->q);
  poll->triggered = false;
  poll->refs = LIST_INIT;
}

int vfs_poll(struct apos_pollfd fds[], apos_nfds_t nfds, int timeout_ms) {
  int result = 0;
  poll_state_t poll;
  init_poll_state(&poll);

  // TODO(aoates): test nfds against OPEN_MAX.
  for (size_t i = 0; i < nfds; ++i) fds[i].revents = 0;

  int fds_selected = 0;
  apos_ms_t now = get_time_ms();
  apos_ms_t end_time = now + timeout_ms;
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

    now = get_time_ms();
    if (timeout_ms < 0 || now < end_time) {
      kspin_lock(&g_poll_lock);
      if (poll.triggered)
        result = SWAIT_DONE;
      else
        result = scheduler_wait_on_splocked(
            &poll.q, timeout_ms < 0 ? -1 : (long)(end_time - now),
            &g_poll_lock);
      kspin_unlock(&g_poll_lock);

      if (result == SWAIT_INTERRUPTED) {
        result = -EINTR;
        break;
      } else if (result == SWAIT_TIMEOUT) {
        result = 0;
        break;
      }
    }
  } while (fds_selected == 0 && (timeout_ms < 0 || now < end_time));
  poll_cancel(&poll);

  if (result == 0) result = fds_selected;

  return result;
}

void poll_assert_empty_event(const pollable_t* poll_event) {
  kspin_lock(&g_poll_lock);
  KASSERT(list_empty(&poll_event->refs));
  kspin_unlock(&g_poll_lock);
}
