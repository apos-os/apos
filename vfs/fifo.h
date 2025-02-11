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

#ifndef APOO_VFS_FIFO_H
#define APOO_VFS_FIFO_H

#include <stdbool.h>
#include <stddef.h>

#include "common/circbuf.h"
#include "proc/kthread.h"
#include "user/include/apos/posix_types.h"
#include "vfs/poll.h"

#define APOS_FIFO_BUF_SIZE 1024

// Equivalent to POSIX's PIPE_BUF.
#define APOS_FIFO_MAX_ATOMIC_WRITE 512

typedef enum {
  FIFO_READ,
  FIFO_WRITE,
} fifo_mode_t;

// State of a FIFO, named or anonymous.
typedef struct {
  kmutex_t mu;
  char buf[APOS_FIFO_BUF_SIZE];
  circbuf_t cbuf;

  kthread_queue_t read_queue;
  kthread_queue_t write_queue;

  int num_readers;
  int num_writers;

  pollable_t poll_event;
  bool hup;  // Have we ever had a writer?
} apos_fifo_t;

void fifo_init(apos_fifo_t* fifo);

// Clean up a FIFO.  It must be closed by all readers and writers.  Does not
// free the apos_fifo_t.
void fifo_cleanup(apos_fifo_t* fifo);

// Open the FIFO in the current process.  If no readers (for FIFO_WRITE) or
// writers (for FIFO_READ) are available, it will block until one is (if |block|
// is true).  If |block| is false, the FIFO is being opened for writing, and
// there are no readers, returns an error unless |force| is true;
int fifo_open(apos_fifo_t* fifo, fifo_mode_t mode, bool block, bool force);

// Close the FIFO.  The given mode must match the mode given with fifo_open().
void fifo_close(apos_fifo_t* fifo, fifo_mode_t mode);

ssize_t fifo_read(apos_fifo_t* fifo, void* buf, size_t len, bool block);
ssize_t fifo_write(apos_fifo_t* fifo, const void* buf, size_t len, bool block);
int fifo_poll(apos_fifo_t* fifo, kmode_t mode, short event_mask,
              poll_state_t* poll);

#endif
