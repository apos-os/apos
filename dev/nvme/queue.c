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

#include <stddef.h>

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

  KLOG(DEBUG, "NVMe: allocated queue %d sq: %" PRIxADDR " cq: %" PRIxADDR "\n",
       id, q->sq, q->cq);

  q->id = id;
  q->cq_io.type = IO_MEMORY;
  q->cq_io.base = q->cq;
  q->doorbell_io.type = ctrl->cfg_io.type;
  q->doorbell_io.base =
      ctrl->cfg_io.base + 0x1000 + id * 2 * ctrl->doorbell_stride;
  q->cq_doorbell_offset = ctrl->doorbell_stride;

  q->sq_entries = NVME_QUEUE_SZ / sizeof(nvme_cmd_t);
  q->cq_entries = NVME_QUEUE_SZ / sizeof(nvme_completion_t);

  q->sq_head = q->sq_tail = q->cq_head = 0;
  q->phase = 1;
  // Zero the queues --- required for phase bits.
  kmemset((void*)q->sq, 0, NVME_QUEUE_SZ);
  kmemset((void*)q->cq, 0, NVME_QUEUE_SZ);
  q->next_cmd_id = 0;
  return 0;
}

int nvmeq_submit(nvme_queue_t* q, const nvme_cmd_t* cmd) {
  if ((q->sq_tail + 1) % q->sq_entries == q->sq_head) {
    KLOG(DEBUG, "NVMe queue %d: sq full, unable to submit command %d\n",
         q->id, cmd->cmd_id);
    return -ENOMEM;
  }

  void* cmd_dst = (void*)(q->sq + q->sq_tail * sizeof(nvme_cmd_t));
  kmemcpy(cmd_dst, cmd, sizeof(nvme_cmd_t));
  // TODO(aoates): do we need a memory barrier of some sort?

  // Increment the tail pointer and ring the doorbell.
  q->sq_tail = (q->sq_tail + 1) % q->sq_entries;
  io_write32(q->doorbell_io, 0, q->sq_tail);
  return 0;
}

int nvmeq_get_completions(nvme_queue_t* q, nvme_completion_t* comps,
                          size_t max_comps) {
  const nvme_completion_t* qcomp = (const nvme_completion_t*)q->cq;
  size_t count = 0;
  KASSERT_DBG((q->phase & 0x1) == q->phase);
  while (count < max_comps) {
    // The controller may be concurrently modifying this memory, so use IO
    // functions to read rather than examining memory directly.
    uint16_t status_phase =
        io_read16(q->cq_io, q->cq_head * sizeof(nvme_completion_t) +
                                offsetof(nvme_completion_t, status_phase));
    if (NVME_PHASE(status_phase) != q->phase) {
      break;
    }

    kmemcpy(&comps[count], &qcomp[q->cq_head], sizeof(nvme_completion_t));
    KASSERT(comps[count].sq_id == q->id);  // Should handle this gracefully...
    q->cq_head = (q->cq_head + 1) % q->cq_entries;
    if (q->cq_head == 0) {
      q->phase = !q->phase;
      KLOG(DEBUG2, "NVMe: queue %d cq phase switching to %d\n", q->id,
           q->phase);
    }
    q->sq_head = comps[count].sq_headptr;
    count++;
  }

  if (count > 0) {
    io_write32(q->doorbell_io, q->cq_doorbell_offset, q->cq_head);
  }
  return count;
}
