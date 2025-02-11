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

// Functions for DMA access to ATA drives and the DMA busmaster.
#ifndef APOO_DEV_ATA_DMA_H
#define APOO_DEV_ATA_DMA_H

#include "dev/ata/ata-internal.h"
#include "dev/ata/queue.h"

// Initialize the DMA subsytem that talks to the PIIX(3) controller.
void dma_init(void);

// Perform the given operation using DMA.  Records success or failure in the
// op's status (and out_len) fields.
void dma_perform_op(ata_disk_op_t* op);

// Finish a DMA transfer.  Called from the interrupt handler after the transfer
// has completed (fully or with an error) to reset the DMA.  If the channel has
// a pending op, copies any data from the DMA buffer as needed.
//
// The channel must be locked when this is called.
void dma_finish_transfer(ata_channel_t* channel);

#endif
