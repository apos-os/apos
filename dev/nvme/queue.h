// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

// Low-level NVMe queue manipulation functions.
#ifndef APOO_DEV_NVME_QUEUE_H
#define APOO_DEV_NVME_QUEUE_H

#include "common/types.h"
#include "dev/io.h"
#include "dev/nvme/command.h"

struct nvme_ctrl;

typedef uint16_t nvme_queue_id_t;

typedef struct {
  nvme_queue_id_t id;

  // Virtual address of the submission and completion queues.
  addr_t sq;
  addr_t cq;
  int sq_entries;
  int cq_entries;
  int sq_head;  // Signalled by the controller.
  int sq_tail;  // We control this.
  int cq_head;

  int phase;
  devio_t cq_io;
  devio_t doorbell_io;
  int cq_doorbell_offset;

  uint16_t next_cmd_id;
} nvme_queue_t;

// Initialize a queue with the given ID for the controller.  Does _not_ actually
// create or manipulate the controller, only the data structures.
int nvmeq_init(struct nvme_ctrl* ctrl, nvme_queue_id_t id, nvme_queue_t* q);

// Submit a command to the queue.  If there is no space in the queue, fails.
// TODO(aoates): define a more efficient version of this that doesn't require
// copying the command (the caller can claim a spot in the queue and construct
// in-place).
int nvmeq_submit(nvme_queue_t* q, const nvme_cmd_t* cmd);

// Read some number of completions from the queue's completion queue.  If none
// are available, returns 0.  Returns the number of completions read, or -error.
int nvmeq_get_completions(nvme_queue_t* q, nvme_completion_t* comps,
                          size_t max_comps);

#endif
