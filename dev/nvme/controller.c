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
#include "dev/nvme/controller.h"

#include <stdint.h>

#include "arch/dev/irq.h"
#include "arch/memory/layout.h"
#include "common/endian.h"
#include "common/errno.h"
#include "common/hashtable.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/io.h"
#include "dev/nvme/admin.h"
#include "dev/nvme/command.h"
#include "dev/nvme/queue.h"
#include "memory/kmalloc.h"
#include "memory/page_alloc.h"
#include "proc/defint.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/spinlock.h"
#include "util/flag_printf.h"

#define KLOG(...) klogfm(KL_NVME, __VA_ARGS__)

#define NVME_ADMIN_QUEUE 0

#define CTRL_CAP 0
#define CTRL_VS 0x8
#define CTRL_INTMS 0xc
#define CTRL_INTMC 0x10
#define CTRL_CC 0x14
#define CTRL_CSTS 0x1c
#define CTRL_AQA 0x24
#define CTRL_ASQ 0x28
#define CTRL_ACQ 0x30

// Bits in the CAP register.
#define CAP_MPSMAX_OFFSET 52
#define CAP_MPSMIN_OFFSET 48
#define CAP_CSS_OFFSET 37
#define CAP_DSTRD_OFFSET 32

// Bits in the CC register.
#define CC_CRIME (1 << 24)
#define CC_IOCQES_OFFSET 20
#define CC_IOCQES_MASK (0xf << CC_IOCQES_OFFSET)
#define CC_IOSQES_OFFSET 16
#define CC_IOSQES_MASK (0xf << CC_IOSQES_OFFSET)
#define CC_AMS_OFFSET 11
#define CC_AMS_MASK (0x7 << CC_AMS_OFFSET)
#define CC_MPS_OFFSET 7
#define CC_MPS_MASK (0xf << CC_MPS_OFFSET)
#define CC_CSS_OFFSET 4
#define CC_CSS_MASK (0x7 << CC_CSS_OFFSET)
#define CC_EN 1

#define NVME_CSS_NVM_CMDSET 1

// Bits in the CSTS register.
#define CSTS_CFS 2
#define CSTS_RDY 1

// The memory page size value to use.
#define NVME_MPS 0  // 2^(12 + 0) = 4096
_Static_assert(PAGE_SIZE == 1 << (12 + NVME_MPS), "Bad NVME_MPS");

// Values to use for IOCQES and IOSQES.
#define NVME_IOCQES 4
#define NVME_IOSQES 6
_Static_assert(sizeof(nvme_completion_t) == (1 << NVME_IOCQES),
               "Bad NVME_IOCQES");
_Static_assert(sizeof(nvme_cmd_t) == (1 << NVME_IOSQES), "Bad NVME_IOSQES");

#define NVME_BLOCKING_TIMEOUT_MS 500

static const flag_spec_t kNvmeCapFields[] = {
  FLAG_SPEC_FLAG("CRIMS", 1ll << 60),
  FLAG_SPEC_FLAG("CRWMS", 1ll << 59),
  FLAG_SPEC_FLAG("NSSS", 1ll << 58),
  FLAG_SPEC_FLAG("CMBS", 1ll << 57),
  FLAG_SPEC_FLAG("PMRS", 1ll << 56),
  FLAG_SPEC_FIELD2("MPSMAX", 4, CAP_MPSMAX_OFFSET),
  FLAG_SPEC_FIELD2("MPSMIN", 4, CAP_MPSMIN_OFFSET),
  FLAG_SPEC_FIELD2("CPS", 2, 46),
  FLAG_SPEC_FLAG("BPS", 1ll << 45),
  FLAG_SPEC_FIELD2("CSS", 8, CAP_CSS_OFFSET),
  FLAG_SPEC_FLAG("NSSRS", 1ll << 36),
  FLAG_SPEC_FIELD2("DSTRD", 4, CAP_DSTRD_OFFSET),
  FLAG_SPEC_FIELD2("TO", 8, 24),
  FLAG_SPEC_FIELD2("AMS", 2, 17),
  FLAG_SPEC_FLAG("CQR", 1ll << 16),
  FLAG_SPEC_FIELD2("MQES", 16, 0),
  FLAG_SPEC_END,
};

static inline ALWAYS_INLINE uint32_t txnkey(nvme_queue_id_t q,
                                            uint16_t cmd_id) {
  return (q << 16) | cmd_id;
}

int nvme_submit(nvme_ctrl_t* ctrl, nvme_transaction_t* txn) {
  // TODO(aoates): support IO queues.
  KASSERT(txn->queue == 0);
  KASSERT(txn->queue >= 0);
  KASSERT(txn->queue <= INT16_MAX);

  nvme_queue_t* q = &ctrl->admin_q;
  kspin_lock(&ctrl->lock);
  txn->cmd.cmd_id = q->next_cmd_id++;
  int result = nvmeq_submit(q, &txn->cmd);
  if (result) {
    kspin_unlock(&ctrl->lock);
    return result;
  }

  uint32_t key = txnkey(txn->queue, txn->cmd.cmd_id);
  htbl_put(&ctrl->pending, key, txn);
  kspin_unlock(&ctrl->lock);
  return 0;
}

#define NVMEC_COMPS_BATCH_SIZE 10

static void nvmec_check_queue(nvme_ctrl_t* ctrl, nvme_queue_t* q) {
  // TODO(aoates): avoid the double copy here.
  nvme_completion_t comps[NVMEC_COMPS_BATCH_SIZE];
  nvme_transaction_t* txns[NVMEC_COMPS_BATCH_SIZE];

  while (true) {
    kspin_lock(&ctrl->lock);
    int result = nvmeq_get_completions(q, comps, NVMEC_COMPS_BATCH_SIZE);
    if (result < 0) {
      KLOG(WARNING, "NVMe: unable to get completions from queue %d: %s\n",
           q->id, errorname(-result));
      kspin_unlock(&ctrl->lock);
      return;
    } else if (result == 0) {
      KLOG(DEBUG3, "NVMe: no completions on queue %d\n", q->id);
      kspin_unlock(&ctrl->lock);
      return;
    }

    KLOG(DEBUG2, "NVMe: found %d completions on queue %d\n", result, q->id);

    const int num_comps = result;
    for (int i = 0; i < num_comps; ++i) {
      void* val = NULL;
      uint32_t key = txnkey(q->id, comps[i].cmd_id);
      result = htbl_get(&ctrl->pending, key, &val);
      KASSERT(result == 0);
      txns[i] = (nvme_transaction_t*)val;
    }
    kspin_unlock(&ctrl->lock);

    for (int i = 0; i < num_comps; ++i) {
      txns[i]->result = comps[i];
      txns[i]->done_cb(txns[i], txns[i]->cb_arg);
    }
  }
}

static void nvmec_defint(void* arg) {
  nvme_ctrl_t* ctrl = (nvme_ctrl_t*)arg;
  KLOG(DEBUG2, "NVMe: handling deferred interrupt\n");

  nvmec_check_queue(ctrl, &ctrl->admin_q);
}

static void nvme_irq(void* arg) {
  KLOG(DEBUG3, "NVMe: IRQ received\n");
  // TODO(aoates): according to the spec, we should have to consume all the
  // completions to clear the interrupt, but qemu doesn't do that.
  defint_schedule(&nvmec_defint, arg);
}

// Example CAP contents from riscv64 qemu:
// [ MPSMAX(4) MPSMIN(0) CPS(0) CSS(193) DSTRD(0) TO(15) AMS(0) CQR MQES(2047) ]
static bool check_cap(uint64_t cap, nvme_ctrl_t* ctrl) {
  int mps_max = (cap >> 52) & 0xf;
  int mps_min = (cap >> 48) & 0xf;
  if (NVME_MPS < mps_min || NVME_MPS > mps_max) {
    KLOG(WARNING, "NVMe: page size (MPS) of %d is unsupported\n", NVME_MPS);
    return false;
  }

  uint32_t css = (cap >> CAP_CSS_OFFSET) & 0xff;
  if (!(css & NVME_CSS_NVM_CMDSET)) {
    KLOG(WARNING, "NVMe: controller doesn't support NVM IO command sets\n");
    return false;
  }

  uint32_t dstrd = (cap >> CAP_DSTRD_OFFSET) & 0x0f;
  ctrl->doorbell_stride = 1 << (2 + dstrd);

  return true;
}

// Set baseline configuration.
static void configure_ctrl(nvme_ctrl_t* ctrl) {
  uint32_t cc = io_read32(ctrl->cfg_io, CTRL_CC);
  KLOG(DEBUG2, "NVMe: original CC register: 0x%x\n", cc);

  // Set AMS to zero (round robin).
  cc &= ~CC_AMS_MASK;

  // Set MPS.
  cc &= ~CC_MPS_MASK;
  cc |= (NVME_MPS << CC_MPS_OFFSET);

  // Enable the NVM command set (set CC.CSS to 000b).
  cc &= ~CC_CSS_MASK;

  // Set IO queue entry sizes.  Note that at this point, we don't actually know
  // what IO command sets are supported --- however qemu until very recently
  // (fixed in commit 6a33f2e92) requires these be set to enable the controller.
  // So guess based on our standard command sizes.
  cc &= ~CC_IOCQES_MASK;
  cc |= (NVME_IOCQES << CC_IOCQES_OFFSET);
  cc &= ~CC_IOSQES_MASK;
  cc |= (NVME_IOSQES << CC_IOSQES_OFFSET);

  KLOG(DEBUG2, "NVMe: new CC register: 0x%x\n", cc);
  io_write32(ctrl->cfg_io, CTRL_CC, cc);
}

// Allocate and set up the admin command and completion queues.
static void configure_admin_queues(nvme_ctrl_t* ctrl) {
  int result = nvmeq_init(ctrl, NVME_ADMIN_QUEUE, &ctrl->admin_q);
  KASSERT(result == 0);

  KLOG(DEBUG,
       "NVMe: configuring admin queues (%d command entries, "
       "%d completion entries)\n",
       ctrl->admin_q.sq_entries, ctrl->admin_q.cq_entries);
  KASSERT(ctrl->admin_q.sq_entries <= 4096);
  KASSERT(ctrl->admin_q.cq_entries <= 4096);
  uint32_t aqa =
      ((ctrl->admin_q.cq_entries - 1) << 16) + (ctrl->admin_q.sq_entries - 1);
  io_write32(ctrl->cfg_io, CTRL_AQA, aqa);

  io_write64(ctrl->cfg_io, CTRL_ASQ, virt2phys(ctrl->admin_q.sq));
  io_write64(ctrl->cfg_io, CTRL_ACQ, virt2phys(ctrl->admin_q.cq));
}

static void configure_interrupts(nvme_ctrl_t* ctrl) {
  uint32_t intmask = io_read32(ctrl->cfg_io, CTRL_INTMS);
  KLOG(DEBUG2, "NVMe: initial interrupt mask 0x%x\n", intmask);

  register_irq_handler(ctrl->irq, &nvme_irq, ctrl);

  // Enable all interrupts.
  io_write32(ctrl->cfg_io, CTRL_INTMC, UINT32_MAX);
}

static void enable_ctrl(nvme_ctrl_t* ctrl) {
  uint32_t cc = io_read32(ctrl->cfg_io, CTRL_CC);
  KASSERT(!(cc & CC_EN));  // Should be disabled.
  cc |= CC_EN;
  io_write32(ctrl->cfg_io, CTRL_CC, cc);
}

static void txn_done(nvme_transaction_t* txn, void* arg) {
  scheduler_wake_all((kthread_queue_t*)arg);
}

int nvme_submit_blocking(nvme_ctrl_t* ctrl, nvme_transaction_t* txn,
                         int timeout_ms) {
  KASSERT(txn->done_cb == NULL);
  KASSERT(txn->cb_arg == NULL);

  kthread_queue_t waitq;
  kthread_queue_init(&waitq);
  txn->done_cb = &txn_done;
  txn->cb_arg = &waitq;

  DEFINT_PUSH_AND_DISABLE();
  int result = nvme_submit(ctrl, txn);
  if (result != 0) {
    DEFINT_POP();
    goto done;
  }

  result = scheduler_wait_on_interruptable(&waitq, timeout_ms);
  DEFINT_POP();
  if (result == SWAIT_TIMEOUT) {
    result = -ETIMEDOUT;
    goto done;
  } else if (result == SWAIT_INTERRUPTED) {
    result = -EINTR;
    goto done;
  }
  KASSERT_DBG(result == SWAIT_DONE);

  if (NVME_STATUS(txn->result.status_phase) != 0) {
    KLOG(WARNING, "NVMe: command failed: NVMe error 0x%x\n",
         NVME_STATUS(txn->result.status_phase));
    result = -EPROTO;
    goto done;
  }
  KASSERT_DBG(result == 0);

done:
  txn->done_cb = NULL;
  txn->cb_arg = NULL;
  return result;
}

static int send_identify(nvme_ctrl_t* ctrl) {
  nvme_transaction_t txn;
  kmemset(&txn, 0, sizeof(txn));

  phys_addr_t buffer = page_frame_alloc();
  txn.cmd.dptr[0] = buffer;
  txn.cmd.dptr[1] = 0;
  txn.cmd.opcode = 0x06;  // Identify admin command.
  uint8_t cns = 0x01;  // Identify controller data.
  txn.cmd.cdw10 = cns;
  txn.cmd.nsid = 0;
  txn.queue = 0;

  int result = nvme_submit_blocking(ctrl, &txn, NVME_BLOCKING_TIMEOUT_MS);
  if (result != 0) {
    KLOG(WARNING, "NVMe: Identify Controller command failed: %s\n",
         errorname(-result));
    page_frame_free(buffer);
    return result;
  }

  nvme_admin_parse_identify_ctrl((void*)phys2virt(buffer), &ctrl->info);
  page_frame_free(buffer);

  KLOG(DEBUG, "NVMe controller identify info:\n");
  KLOG(DEBUG, "  PCI vendor ID: 0x%x\n", ctrl->info.pci_vendor_id);
  KLOG(DEBUG, "  PCI subsystem vendor ID: 0x%x\n",
       ctrl->info.pci_subsys_vendor_id);
  KLOG(DEBUG, "  Serial number: %s\n", ctrl->info.serial);
  KLOG(DEBUG, "  Model: %s\n", ctrl->info.model);
  KLOG(DEBUG, "  Firmware revision: %s\n", ctrl->info.firmware_rev);
  KLOG(DEBUG, "  MDTS: %d\n", ctrl->info.mdts);
  KLOG(DEBUG, "  Controller ID: %d\n", ctrl->info.ctrl_id);
  KLOG(DEBUG, "  Controller type: %d\n", ctrl->info.ctrl_type);
  KLOG(DEBUG, "  SQES: %d to %d bytes\n", ctrl->info.sqes_min_bytes,
       ctrl->info.sqes_max_bytes);
  KLOG(DEBUG, "  CQES: %d to %d bytes\n", ctrl->info.cqes_min_bytes,
       ctrl->info.cqes_max_bytes);
  KLOG(DEBUG, "  Max CMD: %d\n", ctrl->info.max_cmd);
  return 0;
}

// Sends an identify namespace command.  Assumes the transaction is already set
// up other than the nsid;
static int identify_ns(nvme_ctrl_t* ctrl, nvme_transaction_t* txn,
                       nvme_namespace_t* ns) {
  txn->cmd.cdw10 = 0;  // CNS = identify namespace
  txn->cmd.nsid = ns->nsid;

  int result = nvme_submit_blocking(ctrl, txn, NVME_BLOCKING_TIMEOUT_MS);
  if (result != 0) {
    return result;
  }

  const void* buf = (const void*)phys2virt(txn->cmd.dptr[0]);
  ns->ns_size = ltoh64(*(const uint64_t*)buf);
  ns->ns_capacity = ltoh64(*(const uint64_t*)(buf + 8));
#if ARCH_IS_64_BIT
  uint64_t ns_utilization = ltoh64(*(const uint64_t*)(buf + 8));
#endif
  int num_lba_fmts = *(const uint8_t*)(buf + 25);
  uint8_t flbas = *(const uint8_t*)(buf + 26);
  int lba_fmt_idx = (flbas & 0x0f);
  if (num_lba_fmts > 16) {
    lba_fmt_idx |= ((flbas >> 1) & 0x3);
  }
  bool lba_metadata_in_block = flbas & 0x10;

  KLOG(DEBUG2, "  Namespace: %u\n", ns->nsid);
  // TODO(aoates): enable this for 32-bit when %ll is implemented in kprintf.
#if ARCH_IS_64_BIT
  _Static_assert(sizeof(long) == 8, "bad long size");
  KLOG(DEBUG2, "    Size:        %lu blocks\n", ns->ns_size);
  KLOG(DEBUG2, "    Capacity:    %lu blocks\n", ns->ns_capacity);
  KLOG(DEBUG2, "    Utilization: %lu blocks\n", ns_utilization);
#endif
  KLOG(DEBUG2, "    Num LBA formats: %d\n", num_lba_fmts);
  KLOG(DEBUG2, "    FLBAS: %x (LBA format %d; metadata in block: %d)\n", flbas,
       lba_fmt_idx, lba_metadata_in_block);
  KASSERT(lba_fmt_idx >= 0 && lba_fmt_idx < num_lba_fmts);

  KASSERT(num_lba_fmts <= 64);
  for (int i = 0; i < num_lba_fmts; ++i) {
    uint32_t lba_fmt =
        ltoh32(*(const uint32_t*)(buf + 128 + sizeof(uint32_t) * i));
    int lba_rp = (lba_fmt >> 24) & 0x3;
    int lba_data_size = 1 << ((lba_fmt >> 16) & 0xff);
    int lba_metadata_size = lba_fmt & 0xffff;
    KLOG(DEBUG2,
         "    "
         "LBA FMT %d: RP=%d; data_size=%d bytes; metadata_size=%d bytes%s\n",
         i, lba_rp, lba_data_size, lba_metadata_size,
         (i == lba_fmt_idx) ? " [formatted]" : "");
    if (i == lba_fmt_idx) {
      ns->lba_data_bytes = lba_data_size;
      ns->lba_metadata_bytes = lba_metadata_size;
    }
  }

  // TODO(aoates): per the spec, we're supposed to query io-command-set-specific
  // controller, namespace, etc commands now.

  return 0;
}

static int get_namespaces(nvme_ctrl_t* ctrl) {
  nvme_transaction_t txn;
  ZERO_STRUCT(txn);

  phys_addr_t buffer = page_frame_alloc();
  txn.cmd.dptr[0] = buffer;
  txn.cmd.dptr[1] = 0;
  txn.cmd.opcode = 0x06;  // Identify admin command.
  uint8_t cns = 0x07;  // Active namespace ID list for IO command set
  txn.cmd.cdw10 = cns;
  txn.cmd.cdw11 = 0;  // Command set identifier in top 8 bits; 0 for NVM cs.
  txn.cmd.nsid = 0;  // Give all namespaces (up to 1024).
  txn.queue = 0;

  int result = nvme_submit_blocking(ctrl, &txn, NVME_BLOCKING_TIMEOUT_MS);
  if (result != 0) {
    KLOG(WARNING, "NVMe: get active namespaces command failed: %s\n",
         errorname(-result));
    page_frame_free(buffer);
    return result;
  }

  const uint32_t* nsbuf = (const uint32_t*)phys2virt(buffer);
  while (nsbuf[ctrl->num_ns] != 0) {
    ctrl->num_ns++;
  }

  KLOG(DEBUG, "NVMe: found %zu active namespaces\n", ctrl->num_ns);
  if (ctrl->num_ns > 0) {
    ctrl->namespaces =
        (nvme_namespace_t*)kmalloc(sizeof(nvme_namespace_t) * ctrl->num_ns);
    for (size_t i = 0; i < ctrl->num_ns; ++i) {
      ctrl->namespaces[i].nsid = ltoh32(nsbuf[i]);
      result = identify_ns(ctrl, &txn, &ctrl->namespaces[i]);
      if (result) {
        KLOG(WARNING, "NVMe: identify namespace command failed: %s\n",
             errorname(-result));
        page_frame_free(buffer);
        return result;
      }
    }
  }

  page_frame_free(buffer);
  return 0;
}

static nvme_queue_t* get_queue(nvme_ctrl_t* ctrl, nvme_queue_id_t id) {
  KASSERT(id < ctrl->num_io_queues + 1);
  if (id == 0) {
    return &ctrl->admin_q;
  } else {
    return &ctrl->io_q[id - 1];
  }
}

static int create_io_queue(nvme_ctrl_t* ctrl, nvme_queue_id_t q_id) {
  nvme_queue_t* q = get_queue(ctrl, q_id);
  KASSERT(q != NULL);
  int result = nvmeq_init(ctrl, q_id, q);
  if (result != 0) {
    return result;
  }

  // Create the completion queue.
  nvme_transaction_t txn;
  ZERO_STRUCT(txn);
  txn.cmd.dptr[0] = virt2phys(q->cq);
  txn.cmd.opcode = 0x05;  // Create completion queue.
  KASSERT(q->cq_entries > 0);
  KASSERT(q->cq_entries <= (int)UINT16_MAX);
  KASSERT(q_id > 0);
  txn.cmd.cdw10 = ((q->cq_entries - 1) << 16) | q_id;
  txn.cmd.cdw11 = 0       // We're using pin-based interrupts
                  | 0x2   // Interrupts enabled.
                  | 0x1;  // Physically-contiguous buffer.
  txn.queue = 0;  // Command for admin queue.

  result = nvme_submit_blocking(ctrl, &txn, NVME_BLOCKING_TIMEOUT_MS);
  if (result) {
    KLOG(WARNING, "NVMe: unable to create completion queue %d: %s\n",
         q_id, errorname(-result));
    return result;
  }

  // Create the submission queue.
  ZERO_STRUCT(txn);
  txn.cmd.dptr[0] = virt2phys(q->sq);
  txn.cmd.opcode = 0x01;  // Create submission queue.
  KASSERT(q->sq_entries > 0);
  KASSERT(q->sq_entries <= (int)UINT16_MAX);
  txn.cmd.cdw10 = ((q->sq_entries - 1) << 16) | q_id;
  txn.cmd.cdw11 = (q_id << 16)  // Use the paired completion queue.
                  | 0x1;        // Physically-contiguous buffer.
  txn.queue = 0;  // Command for admin queue.

  result = nvme_submit_blocking(ctrl, &txn, NVME_BLOCKING_TIMEOUT_MS);
  if (result) {
    KLOG(WARNING, "NVMe: unable to create submission queue %d: %s\n",
         q_id, errorname(-result));
    return result;
  }

  return 0;
}

static int setup_io_queues(nvme_ctrl_t* ctrl) {
  ctrl->num_io_queues = 1;
  ctrl->io_q = KMALLOC(nvme_queue_t);
  return create_io_queue(ctrl, 1);
}

static bool ctrl_is_ready(const nvme_ctrl_t* ctrl) {
  uint32_t csts = io_read32(ctrl->cfg_io, CTRL_CSTS);
  // TODO(aoates): handle fatal errors more gracefully.
  KASSERT_MSG(!(csts & CSTS_CFS), "NVMe controller hit fatal error");
  return csts & CSTS_RDY;
}

static nvme_ctrl_t* nvme_ctrl_alloc(void) {
  nvme_ctrl_t* ctrl = KMALLOC(nvme_ctrl_t);
  kmemset(ctrl, 0, sizeof(nvme_ctrl_t));
  htbl_init(&ctrl->pending, 10);
  ctrl->lock = KSPINLOCK_NORMAL_INIT;
  ctrl->namespaces = NULL;
  ctrl->num_ns = 0;
  ctrl->num_io_queues = 0;
  ctrl->io_q = NULL;
  return ctrl;
}

static bool nvme_ctrl_init(nvme_ctrl_t* ctrl) {
  uint64_t cap = io_read64(ctrl->cfg_io, CTRL_CAP);
  char buf[200];
  flag_sprintf(buf, cap, kNvmeCapFields);
  KLOG(DEBUG, "NVMe CAP: %s\n", buf);

  uint32_t vs = io_read32(ctrl->cfg_io, CTRL_VS);
  KLOG(DEBUG, "NVMe VS: 0x%x\n", vs);
  if (vs != 0x10400) {
    KLOG(INFO, "Unsupported NVMe version: 0x%x\n", vs);
    return false;
  }

  // Check that the capabilities are supportable.
  if (!check_cap(cap, ctrl)) {
    return false;
  }

  configure_ctrl(ctrl);
  configure_admin_queues(ctrl);
  configure_interrupts(ctrl);
  enable_ctrl(ctrl);

  // Wait for controller to become ready.
  for (int i = 0; !ctrl_is_ready(ctrl) && i < 10; ++i) {
    ksleep(100);
  }
  if (!ctrl_is_ready(ctrl)) {
    KLOG(WARNING, "NVME: controller didn't become ready\n");
    return false;
  }

  if (send_identify(ctrl) != 0) {
    return false;
  }

  if (get_namespaces(ctrl) != 0) {
    return false;
  }

  if (setup_io_queues(ctrl) != 0) {
    return false;
  }

  return true;
}

void nvme_ctrl_pci_init(pci_device_t* pcidev) {
  KLOG(DEBUG, "Enabling PCI bus mastering\n");
  pci_read_status(pcidev);  // Redundant, but let's be careful.
  pcidev->command |= PCI_CMD_BUSMASTER_ENABLE;
  pci_write_status(pcidev);

  if (!pcidev->bar[0].valid) {
    KLOG(WARNING, "NVMe controller %d.%d(%d) missing BAR0\n",
         pcidev->bus, pcidev->device, pcidev->function);
    return;
  }

  nvme_ctrl_t* ctrl = nvme_ctrl_alloc();
  ctrl->cfg_io = pcidev->bar[0].io;
  ctrl->irq = pcidev->host_irq;
  if (!nvme_ctrl_init(ctrl)) {
    KLOG(WARNING, "NVMe controller %d.%d(%d): failed to initialized\n",
         pcidev->bus, pcidev->device, pcidev->function);
  }
  KLOG(INFO, "NVMe controller %d.%d(%d): initialized and enabled\n",
       pcidev->bus, pcidev->device, pcidev->function);
}
