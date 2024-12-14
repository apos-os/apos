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
#ifndef APOO_DEV_NVME_CONTROLLER_H
#define APOO_DEV_NVME_CONTROLLER_H

#include "common/hashtable.h"
#include "dev/block_dev.h"
#include "dev/nvme/admin.h"
#include "dev/nvme/command.h"
#include "dev/nvme/queue.h"
#include "dev/pci/pci-driver.h"
#include "proc/spinlock.h"
#include "user/include/apos/dev.h"

typedef uint32_t nvme_nsid_t;

typedef struct {
  nvme_nsid_t nsid;

  uint64_t ns_size;
  uint64_t ns_capacity;
  int lba_data_bytes;
  int lba_metadata_bytes;

  apos_dev_t bd_id;
  block_dev_t bd;
} nvme_namespace_t;

typedef struct nvme_ctrl {
  devio_t cfg_io;
  irq_t irq;

  int doorbell_stride;

  nvme_queue_t admin_q;
  int num_io_queues;
  nvme_queue_t* io_q;  // Starting at queue ID 1.

  // Pending transactions.
  htbl_t pending;

  // Protects the pending transactions and pending table.
  kspinlock_t lock;

  // Information from the Identify Controller command.
  nvme_admin_identify_ctrl_t info;

  // Active namespaces.
  size_t num_ns;
  nvme_namespace_t* namespaces;
} nvme_ctrl_t;

// A transaction to execute on an NVMe queue.
struct nvme_transaction {
  nvme_queue_id_t queue;
  nvme_cmd_t cmd;
  nvme_completion_t result;  // Will be filled in when the command is finished.

  // Callback to invoke when the command is finished.  May be invoked from a
  // deferred interrupt.  Takes ownership of the nvme_transaction object.
  void (*done_cb)(struct nvme_transaction* txn, void* arg);
  void* cb_arg;
};
typedef struct nvme_transaction nvme_transaction_t;

// Submit the given transaction on the controller.  If the transaction is
// sucessfully submitted, returns 0 and the done callback will later be invoked.
// On error returns -error (and the callback won't be run).
//
// Requires: the controller is locked.
int nvme_submit(nvme_ctrl_t* ctrl, nvme_transaction_t* txn);

// Abandon a submitted transaction.  Guarantees that when it returns either the
// callback has finished running or will never run.
void nvme_abandon(nvme_ctrl_t* ctrl, nvme_transaction_t* txn);

// As with nvme_submit, but blocks until the transaction is complete, or the
// timeout is hit.  Checks the result of the operation and returns an error if
// it fails.  The callback member of txn must be NULL.
int nvme_submit_blocking(nvme_ctrl_t* ctrl, nvme_transaction_t* txn,
                         int timeout_ms);

// Initialize an NVMe controller from a PCI device.
void nvme_ctrl_pci_init(pci_device_t* pcidev);

#endif
