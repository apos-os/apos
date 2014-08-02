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

// Queue of pending ATA operations to apply to a given channel.
#ifndef APOO_DEV_ATA_QUEUE_H
#define APOO_DEV_ATA_QUEUE_H

#include <stdbool.h>
#include <stdint.h>

#include "dev/ata/ata-internal.h"
#include "proc/kthread.h"

// A single operation to apply to a disk.  Associated (on a queue) with a
// particular channel.
struct ata_disk_op {
  // The drive to apply the operation to.
  drive_t* drive;

  // Input parameters.
  bool is_write;  // 1 if writing, 0 if reading.
  uint32_t offset;  // Disk offset to read/write, in sectors.

  // Only one buffer should be set (read_buf if is_write == 0, write_buf if not)
  void* read_buf;  // The buffer (virtual address) to read into.
  const void* write_buf;  // The buffer (virtual address) to write into.

  uint32_t len;  // The length of the buffer (max # of bytes to read);

  // Output parameters (set once the op has finished).
  bool done;
  int status;  // 0 for success, or -errno on error.
  int out_len;  // The actual number of bytes read/written.

  // Thread queue of threads waiting on this op to finish.
  kthread_queue_t waiters;
};
typedef struct ata_disk_op ata_disk_op_t;

#endif
