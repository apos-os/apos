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
#include "vfs/fifo.h"

void fifo_init(apos_fifo_t* fifo) {
  circbuf_init(&fifo->cbuf, fifo->buf, APOS_FIFO_BUF_SIZE);
  kthread_queue_init(&fifo->read_queue);
  kthread_queue_init(&fifo->write_queue);
  fifo->num_readers = 0;
  fifo->num_writers = 0;
}

void fifo_cleanup(apos_fifo_t* fifo) {
  KASSERT(fifo->num_readers == 0);
  KASSERT(fifo->num_writers == 0);
  KASSERT(kthread_queue_empty(&fifo->read_queue));
  KASSERT(kthread_queue_empty(&fifo->write_queue));
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
    // TODO(aoates): make this interruptable and handle signals.
    scheduler_wait_on(queue);
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
      // TODO wake writers
      break;

    case FIFO_WRITE:
      fifo->num_writers--;
      scheduler_wake_all(&fifo->read_queue);
      break;
  }

  KASSERT(fifo->num_readers >= 0);
  KASSERT(fifo->num_writers >= 0);
}

ssize_t fifo_read(apos_fifo_t* fifo, void* buf, size_t len, bool block) {
  KASSERT(fifo->num_readers > 0);
  if (len == 0) return 0;
  else if (fifo->cbuf.len == 0 && fifo->num_writers == 0) return 0;
  else if (fifo->cbuf.len == 0 && !block) return -EAGAIN;

  while (block && fifo->num_writers > 0 && fifo->cbuf.len == 0) {
    // TODO(aoates): make this interruptable and handle signals.
    scheduler_wait_on(&fifo->read_queue);
  }

  int result = circbuf_read(&fifo->cbuf, buf, len);
  if (result > 0) {
    scheduler_wake_all(&fifo->write_queue);
  }
  return result;
}

ssize_t fifo_write(apos_fifo_t* fifo, const void* buf, size_t len, bool block) {
  KASSERT(fifo->num_writers > 0);

  ssize_t bytes_written = 0;
  const size_t min_write = (len <= APOS_FIFO_MAX_ATOMIC_WRITE ? len : 1);
  while (len > 0) {
    while (block && fifo->cbuf.buflen - fifo->cbuf.len < min_write) {
      // TODO(aoates): make this interruptable and handle signals.
      scheduler_wait_on(&fifo->write_queue);
    }

    if (!block && fifo->cbuf.buflen - fifo->cbuf.len < min_write) {
      return -EAGAIN;
    }

    ssize_t result = circbuf_write(&fifo->cbuf, buf, len);
    if (result > 0) {
      scheduler_wake_all(&fifo->read_queue);
      bytes_written += result;

      buf += result;
      len -= result;
    }

    if (!block) break;
  }
  return bytes_written;
}


