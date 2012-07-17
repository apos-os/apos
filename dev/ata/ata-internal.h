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

#ifndef APOO_DEV_ATA_INTERNAL_H
#define APOO_DEV_ATA_INTERNAL_H

#define ATA_DRIVE_MASTER 0
#define ATA_DRIVE_SLAVE  1
#define ATA_BLOCK_SIZE 512

#include "proc/kthread.h"

// dev/ata/queue.h
struct ata_disk_op;

// Contains data about the port offsets for the primary and secondary ATA
// channels.
struct ata_channel {
  uint16_t cmd_offset;  // Port offset for the command block.
  uint16_t ctrl_offset;  // Port offset for the control block.
  // Port offset for the DMA busmaster (if available).
  uint16_t busmaster_offset;
  uint8_t irq;  // The IRQ used by this channel.

  // The currently-pending operation on this channel (for the master or slave),
  // or 0x0 if the channel is free.
  struct ata_disk_op* pending_op;

  // Threads waiting for the channel to be free.
  kthread_queue_t channel_waiters;
};
typedef struct ata_channel ata_channel_t;

struct ata {
  ata_channel_t primary;
  ata_channel_t secondary;
};
typedef struct ata ata_t;

// Data about a particular drive.
struct drive {
  // Meta fields: is the drive present, and supported by the driver.
  uint8_t present;
  uint8_t supported;

  ata_channel_t* channel;
  uint8_t drive_num;  // 0 for master, 1 for slave.

  uint16_t features;  // Feature bits.
  uint16_t cylinders;
  uint16_t heads;
  uint16_t bytes_per_track;
  uint16_t bytes_per_sector;
  uint16_t sectors_per_track;
  char serial[21];  // Null-terminated ASCII serial number.
  uint16_t buf_type;
  uint16_t buf_size;
  uint16_t ecc_bytes;
  char firmware[9];  // Null-terminated firmware version.
  char model[41];  // Null-terminated model number.
  uint16_t features2;

  // Total number of user-addressable sectors in LBA mode.
  uint32_t lba_sectors;

  // TODO(aoates): the rest of the fields.
};
typedef struct drive drive_t;

// Initialize the DMA subsytem that talks to the PIIX(3) controller.
void dma_init();

// Returns the buffer used for DMA.  It is exactly one page long.
void* dma_get_buffer();

// Initiate a DMA transfer on the currently-selected drive on the given channel.
// This is step 1, which sets up and loads the PRDT in the controller, and sets
// the status bits correctly.  If the transfer is a write, the caller should
// have already copied the data into the dma_get_buffer() region.
//
// After calling this, the DMA transfer command must be given to the device, and
// then dma_start_transfer() should be called.
void dma_setup_transfer(ata_channel_t* channel, uint32_t len, uint8_t is_write);

// Step 2 of a DMA.  This actually starts the DMA process in the controller.
// dma_setup_transfer() must have been called already, and the DMA command
// should have already been sent to the device.
void dma_start_transfer(ata_channel_t* channel);

// Finish a DMA transfer.  Called after the transfer has completed (fully or
// with an error) to reset the DMA.
void dma_finish_transfer(ata_channel_t* channel);

#endif
