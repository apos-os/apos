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
#include "vfs/fifo.h"

static short fifo_poll_events(const apos_fifo_t* fifo) {
  short events = 0;
  if (fifo->cbuf.len > 0 && fifo->num_readers > 0) events |= POLLIN;
  if (fifo->cbuf.len < fifo->cbuf.buflen) events |= POLLOUT;
  if (fifo->num_readers == 0) events |= POLLERR;
  // TODO(aoates): handle POLLHUP
  return events;
}

void fifo_init(apos_fifo_t* fifo) {
  circbuf_init(&fifo->cbuf, fifo->buf, APOS_FIFO_BUF_SIZE);
  kthread_queue_init(&fifo->read_queue);
  kthread_queue_init(&fifo->write_queue);
  fifo->num_readers = 0;
  fifo->num_writers = 0;
  poll_init_event(&fifo->poll_event);
}

void fifo_cleanup(apos_fifo_t* fifo) {
  KASSERT(fifo->num_readers == 0);
  KASSERT(fifo->num_writers == 0);
  KASSERT(kthread_queue_empty(&fifo->read_queue));
  KASSERT(kthread_queue_empty(&fifo->write_queue));
  KASSERT(list_empty(&fifo->poll_event.refs));
}

int fifo_open(apos_fifo_t* fifo, fifo_mode_t mode, bool block, bool force) {
  switch (mode) {
    case FIFO_READ:
      fifo->num_readers++;
      break;

    case FIFO_WRITE:
      if (fifo->num_readers == 0 && !block && !force) return -ENXIO;
      fifo->num_writers++;
      break;
  }

  KASSERT(fifo->num_readers >= 0);
  KASSERT(fifo->num_writers >= 0);
  KASSERT(fifo->num_readers > 0 || fifo->num_writers > 0);

  while (block && (fifo->num_readers == 0 || fifo->num_writers == 0)) {
    kthread_queue_t* queue =
        (mode == FIFO_READ) ? &fifo->read_queue : &fifo->write_queue;
    int wait_result = scheduler_wait_on_interruptable(queue, -1);
    if (wait_result == SWAIT_INTERRUPTED) {
      switch (mode) {
        case FIFO_READ: fifo->num_readers--; break;
        case FIFO_WRITE: fifo->num_writers--; break;
      }
      return -EINTR;
    }
  }

  kthread_queue_t* queue =
      (mode == FIFO_READ) ? &fifo->write_queue : &fifo->read_queue;
  scheduler_wake_all(queue);
  return 0;
}

void fifo_close(apos_fifo_t* fifo, fifo_mode_t mode) {
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
}

ssize_t fifo_read(apos_fifo_t* fifo, void* buf, size_t len, bool block) {
  KASSERT(fifo->num_readers > 0);
  if (len == 0) return 0;
  else if (fifo->cbuf.len == 0 && fifo->num_writers == 0) return 0;
  else if (fifo->cbuf.len == 0 && !block) return -EAGAIN;

  while (block && fifo->num_writers > 0 && fifo->cbuf.len == 0) {
    int wait_result = scheduler_wait_on_interruptable(&fifo->read_queue, -1);
    if (wait_result == SWAIT_INTERRUPTED) return -EINTR;
  }

  int result = circbuf_read(&fifo->cbuf, buf, len);
  if (result > 0) {
    scheduler_wake_all(&fifo->write_queue);
    poll_trigger_event(&fifo->poll_event, fifo_poll_events(fifo));
  }
  return result;
}

ssize_t fifo_write(apos_fifo_t* fifo, const void* buf, size_t len, bool block) {
  KASSERT(fifo->num_writers > 0);

  ssize_t bytes_written = 0;
  const size_t min_write = (len <= APOS_FIFO_MAX_ATOMIC_WRITE ? len : 1);
  do {
    while (block && fifo->cbuf.buflen - fifo->cbuf.len < min_write &&
           fifo->num_readers > 0) {
      int wait_result = scheduler_wait_on_interruptable(&fifo->write_queue, -1);
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

int fifo_poll(apos_fifo_t* fifo, short event_mask, poll_state_t* poll) {
  const short masked_events = fifo_poll_events(fifo) & event_mask;
  if (masked_events || !poll)
    return masked_events;

  return poll_add_event(poll, &fifo->poll_event, event_mask);
}
