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

#include "common/errno.h"
#include "common/kassert.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/fifo.h"

static short fifo_poll_events(const apos_fifo_t* fifo) {
  short events = 0;
  if (fifo->cbuf.len > 0 && fifo->num_readers > 0)
    events |= KPOLLIN | KPOLLRDNORM;
  if (fifo->cbuf.len < fifo->cbuf.buflen && fifo->num_writers > 0)
    events |= KPOLLOUT;
  if (fifo->num_readers == 0) events |= KPOLLERR;
  if (fifo->num_writers == 0 && fifo->hup) events |= KPOLLHUP;
  return events;
}

void fifo_init(apos_fifo_t* fifo) {
  kmutex_init(&fifo->mu);
  circbuf_init(&fifo->cbuf, fifo->buf, APOS_FIFO_BUF_SIZE);
  kthread_queue_init(&fifo->read_queue);
  kthread_queue_init(&fifo->write_queue);
  fifo->num_readers = 0;
  fifo->num_writers = 0;
  poll_init_event(&fifo->poll_event);
  fifo->hup = false;
}

void fifo_cleanup(apos_fifo_t* fifo) {
  KASSERT(fifo->num_readers == 0);
  KASSERT(fifo->num_writers == 0);
  KASSERT(kthread_queue_empty(&fifo->read_queue));
  KASSERT(kthread_queue_empty(&fifo->write_queue));
  // This isn't strictly necessary---for us to be cleaning up this fifo, we must
  // have previously closed the last reference, meaning we'd generate a KPOLLERR
  // when num_readers goes to zero.  But generating a KPOLLNVAL here is correct,
  // if redundant.
  poll_trigger_event(&fifo->poll_event, KPOLLNVAL);
  poll_assert_empty_event(&fifo->poll_event);
}

int fifo_open(apos_fifo_t* fifo, fifo_mode_t mode, bool block, bool force) {
  kmutex_lock(&fifo->mu);
  switch (mode) {
    case FIFO_READ:
      fifo->num_readers++;
      break;

    case FIFO_WRITE:
      if (fifo->num_readers == 0 && !block && !force) {
        kmutex_unlock(&fifo->mu);
        return -ENXIO;
      }
      fifo->num_writers++;
      fifo->hup = true;
      break;
  }

  KASSERT(fifo->num_readers >= 0);
  KASSERT(fifo->num_writers >= 0);
  KASSERT(fifo->num_readers > 0 || fifo->num_writers > 0);

  while (block && (fifo->num_readers == 0 || fifo->num_writers == 0)) {
    kthread_queue_t* queue =
        (mode == FIFO_READ) ? &fifo->read_queue : &fifo->write_queue;
    int wait_result = scheduler_wait_on_locked(queue, -1, &fifo->mu);
    if (wait_result == SWAIT_INTERRUPTED) {
      switch (mode) {
        case FIFO_READ: fifo->num_readers--; break;
        case FIFO_WRITE: fifo->num_writers--; break;
      }
      kmutex_unlock(&fifo->mu);
      return -EINTR;
    }
  }

  kthread_queue_t* queue =
      (mode == FIFO_READ) ? &fifo->write_queue : &fifo->read_queue;
  scheduler_wake_all(queue);
  kmutex_unlock(&fifo->mu);
  return 0;
}

void fifo_close(apos_fifo_t* fifo, fifo_mode_t mode) {
  kmutex_lock(&fifo->mu);
  switch (mode) {
    case FIFO_READ:
      fifo->num_readers--;
      scheduler_wake_all(&fifo->write_queue);
      break;

    case FIFO_WRITE:
      fifo->num_writers--;
      scheduler_wake_all(&fifo->read_queue);
      break;
  }
  poll_trigger_event(&fifo->poll_event, fifo_poll_events(fifo));

  KASSERT(fifo->num_readers >= 0);
  KASSERT(fifo->num_writers >= 0);
  kmutex_unlock(&fifo->mu);
}

static ssize_t fifo_read_locked(apos_fifo_t* fifo, void* buf, size_t len, bool block) {
  KASSERT(fifo->num_readers > 0);
  if (len == 0) return 0;
  else if (fifo->cbuf.len == 0 && fifo->num_writers == 0) return 0;
  else if (fifo->cbuf.len == 0 && !block) return -EAGAIN;

  while (block && fifo->num_writers > 0 && fifo->cbuf.len == 0) {
    int wait_result =
        scheduler_wait_on_locked(&fifo->read_queue, -1, &fifo->mu);
    if (wait_result == SWAIT_INTERRUPTED) return -EINTR;
  }

  int result = circbuf_read(&fifo->cbuf, buf, len);
  if (result > 0) {
    scheduler_wake_all(&fifo->write_queue);
    poll_trigger_event(&fifo->poll_event, fifo_poll_events(fifo));
  }
  return result;
}

ssize_t fifo_read(apos_fifo_t* fifo, void* buf, size_t len, bool block) {
  kmutex_lock(&fifo->mu);
  ssize_t result = fifo_read_locked(fifo, buf, len, block);
  kmutex_unlock(&fifo->mu);
  return result;
}

static ssize_t fifo_write_locked(apos_fifo_t* fifo, const void* buf, size_t len, bool block) {
  KASSERT(fifo->num_writers > 0);

  ssize_t bytes_written = 0;
  const size_t min_write = (len <= APOS_FIFO_MAX_ATOMIC_WRITE ? len : 1);
  do {
    while (block && fifo->cbuf.buflen - fifo->cbuf.len < min_write &&
           fifo->num_readers > 0) {
      int wait_result =
          scheduler_wait_on_locked(&fifo->write_queue, -1, &fifo->mu);
      if (wait_result == SWAIT_INTERRUPTED)
        return bytes_written > 0 ? bytes_written : -EINTR;
    }

    if (fifo->num_readers == 0) {
      proc_force_signal(proc_current(), SIGPIPE);
      return -EPIPE;
    }

    if (!block && fifo->cbuf.buflen - fifo->cbuf.len < min_write) {
      return -EAGAIN;
    }

    ssize_t result = circbuf_write(&fifo->cbuf, buf, len);
    if (result > 0) {
      scheduler_wake_all(&fifo->read_queue);
      poll_trigger_event(&fifo->poll_event, fifo_poll_events(fifo));
      bytes_written += result;

      buf += result;
      len -= result;
    }
  } while (block && len > 0);

  return bytes_written;
}

ssize_t fifo_write(apos_fifo_t* fifo, const void* buf, size_t len, bool block) {
  kmutex_lock(&fifo->mu);
  ssize_t result = fifo_write_locked(fifo, buf, len, block);
  kmutex_unlock(&fifo->mu);
  return result;
}

int fifo_poll(apos_fifo_t* fifo, kmode_t mode, short event_mask,
              poll_state_t* poll) {
  kmutex_lock(&fifo->mu);
  if (mode == VFS_O_RDONLY) {
    event_mask &= ~(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND);
  } else if (mode == VFS_O_WRONLY) {
    event_mask &= ~(KPOLLIN | KPOLLRDNORM | KPOLLRDBAND);
  }

  const short masked_events = fifo_poll_events(fifo) & event_mask;
  int result;
  if (masked_events || !poll) {
    result = masked_events;
  } else {
    result = poll_add_event(poll, &fifo->poll_event, event_mask);
  }

  kmutex_unlock(&fifo->mu);
  return result;
}
