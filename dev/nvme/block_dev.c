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
#include "dev/nvme/block_dev.h"

#include "common/kstring.h"
#include "common/math.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "dev/nvme/controller.h"
#include "memory/kmalloc.h"
#include "memory/page_alloc.h"
#include "user/include/apos/dev.h"

#define KLOG(...) klogfm(KL_NVME, __VA_ARGS__)

#define NVME_BLOCK_DEV_TIMEOUT_MS 5000

typedef struct {
  nvme_ctrl_t* ctrl;
  nvme_namespace_t* ns;
} nvme_block_dev_t;

static int nvme_bd_op(struct block_dev* dev, size_t offset_sectors, void* buf,
                      size_t len, bool is_write) {
  nvme_block_dev_t* nvme_bd = (nvme_block_dev_t*)dev->dev_data;
  if (len > PAGE_SIZE) {
    KLOG(WARNING, "NVMe: cannot handle IO larger than a page (size = %zu)\n",
         len);
    len = PAGE_SIZE;
  }

  KASSERT_DBG(nvme_bd->ns->lba_data_bytes == dev->sector_size);
  if (len % nvme_bd->ns->lba_data_bytes != 0) {
    KLOG(WARNING, "NVMe: cannot handle non-block-size ops (len = %zu)\n",
         len);
    return -EINVAL;
  }

  if (len == 0 || offset_sectors >= (size_t)dev->sectors) {
    return 0;
  }
  size_t max_len_sectors = (size_t)dev->sectors - offset_sectors;
  len = min(len, max_len_sectors * dev->sector_size);

  // TODO(aoates): read/write directly into the page rather than bouncing
  // through another buffer.
  phys_addr_t dbuf = page_frame_alloc();
  if (is_write) {
    kmemcpy((void*)phys2virt(dbuf), buf, len);
  }

  nvme_transaction_t txn;
  ZERO_STRUCT(txn);
  txn.cmd.opcode = is_write ? 0x1 : 0x2;
  txn.cmd.nsid = nvme_bd->ns->nsid;
  txn.cmd.dptr[0] = dbuf;
  txn.cmd.cdw10 = offset_sectors & 0xffffffff;
  txn.cmd.cdw11 = (uint64_t)offset_sectors >> 32;
  KASSERT_DBG(nvme_bd->ns->lba_data_bytes == dev->sector_size);
  KASSERT(len % nvme_bd->ns->lba_data_bytes == 0);
  txn.cmd.cdw12 = (len / nvme_bd->ns->lba_data_bytes) - 1;

  KASSERT(nvme_bd->ctrl->num_io_queues == 1);
  txn.queue = nvme_bd->ctrl->io_q[0].id;
  int result =
      nvme_submit_blocking(nvme_bd->ctrl, &txn, NVME_BLOCK_DEV_TIMEOUT_MS);
  if (result != 0) {
    page_frame_free(dbuf);
    return result;
  }

  if (!is_write) {
    kmemcpy(buf, (const void*)phys2virt(dbuf), len);
  }
  page_frame_free(dbuf);
  return len;
}

static int nvme_bd_read(struct block_dev* dev, size_t offset_sectors, void* buf,
                        size_t len, int flags) {
  return nvme_bd_op(dev, offset_sectors, buf, len, false);
}

static int nvme_bd_write(struct block_dev* dev, size_t offset_sectors,
                         const void* buf, size_t len, int flags) {
  return nvme_bd_op(dev, offset_sectors, (void*)buf, len, true);
}

int nvme_create_block_dev(nvme_ctrl_t* ctrl, nvme_namespace_t* ns) {
  nvme_block_dev_t* nvme_bd = KMALLOC(nvme_block_dev_t);
  nvme_bd->ctrl = ctrl;
  nvme_bd->ns = ns;

  // TODO(aoates): should this be the utilized number?  Or the length?
  ns->bd.sectors = ns->ns_size;
  ns->bd.sector_size = ns->lba_data_bytes;
  ns->bd.dev_data = nvme_bd;
  ns->bd.read = &nvme_bd_read;
  ns->bd.write = &nvme_bd_write;

  ns->bd_id = kmakedev(DEVICE_MAJOR_NVME, DEVICE_ID_UNKNOWN);
  return dev_register_block(&ns->bd, &ns->bd_id);
}
