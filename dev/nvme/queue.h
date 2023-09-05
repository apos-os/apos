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

struct nvme_ctrl;

typedef uint16_t nvme_queue_id_t;

typedef struct {
  nvme_queue_id_t id;

  // Virtual address of the submission and completion queues.
  addr_t sq;
  addr_t cq;
  int sq_entries;
  int cq_entries;
  int sq_tail;
  int cq_head;

  devio_t doorbell_io;
} nvme_queue_t;

// Initialize a queue with the given ID for the controller.  Does _not_ actually
// create or manipulate the controller, only the data structures.
int nvmeq_init(struct nvme_ctrl* ctrl, nvme_queue_id_t id, nvme_queue_t* q);

#endif
