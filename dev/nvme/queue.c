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
#include "dev/nvme/queue.h"

#include "arch/memory/layout.h"
#include "common/errno.h"
#include "common/kstring.h"
#include "dev/nvme/command.h"
#include "dev/nvme/controller.h"
#include "memory/page_alloc.h"

#define KLOG(...) klogfm(KL_NVME, __VA_ARGS__)

// The size of the queues allocation for all operations.  We just allocate one
// page for all queues currently, so we don't have to bother with contigous
// pages, scatter-gather lists, etc.
#define NVME_QUEUE_SZ PAGE_SIZE
_Static_assert(NVME_QUEUE_SZ % sizeof(nvme_cmd_t) == 0, "Bad queue size");
_Static_assert(NVME_QUEUE_SZ % sizeof(nvme_completion_t) == 0,
               "Bad queue size");

int nvmeq_init(struct nvme_ctrl* ctrl, nvme_queue_id_t id, nvme_queue_t* q) {
  q->sq = phys2virt(page_frame_alloc());
  if (!q->sq) return -ENOMEM;
  q->cq = phys2virt(page_frame_alloc());
  if (!q->cq) {
    page_frame_free(q->sq);
    return -ENOMEM;
  }

  q->doorbell_io.type = ctrl->cfg_io.type;
  q->doorbell_io.base = ctrl->cfg_io.base + id * 2 * ctrl->doorbell_stride;

  q->sq_entries = NVME_QUEUE_SZ / sizeof(nvme_cmd_t);
  q->cq_entries = NVME_QUEUE_SZ / sizeof(nvme_completion_t);

  q->sq_tail = q->cq_head = 0;
  // Zero the queues --- required for phase bits.
  kmemset((void*)q->sq, 0, NVME_QUEUE_SZ);
  kmemset((void*)q->cq, 0, NVME_QUEUE_SZ);
  return 0;
}
