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

#include <stdbool.h>

#include "dev/io.h"
#include "proc/kthread.h"
#include "proc/tasklet.h"

#define ATA_DRIVE_MASTER 0
#define ATA_DRIVE_SLAVE  1
#define ATA_BLOCK_SIZE 512

// dev/ata/queue.h
struct ata_disk_op;

// Contains data about the port offsets for the primary and secondary ATA
// channels.
struct ata_channel {
  kspinlock_t mu;    // Protects data shared with defints.
  devio_t cmd_io;    // Port offset for the command block.
  devio_t ctrl_io;   // Port offset for the control block.
  // Port offset for the DMA busmaster (if available).
  devio_t busmaster_io;
  uint8_t irq;  // The IRQ used by this channel.

  // Whether or not the channel is in-use.  May be true even if pending_op is
  // NULL (if e.g. the operation was interrupted).
  bool in_use GUARDED_BY(&mu);

  // The currently-pending operation on this channel (for the master or slave).
  // May be NULL even if the channel is in use.
  struct ata_disk_op* pending_op GUARDED_BY(&mu) PT_GUARDED_BY(&mu);

  // Threads waiting for the channel to be free.
  kthread_queue_t channel_waiters GUARDED_BY(&mu);

  tasklet_t tasklet;
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
  bool present;
  bool supported;

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

// Select a drive (ATA_DRIVE_MASTER or ATA_DRIVE_SLAVE) on the given channel.
// The channel must not be in use.
void drive_select(ata_channel_t* channel, uint8_t drive);

// Load the given LBA address and sector count into the appropriate registers.
// The sector count is clamped to the range [1, 256].  Notably, that means you
// can't set a range of zero sectors.
void set_lba(ata_channel_t* channel, uint32_t lba, uint32_t sector_count);

// Issues an ATA command on the given channel, blocking until the BSY flag is
// clear before sending it.  Assumes that any needed parameters (including the
// drive select!) have already been loaded into the appropriate registers.
void send_cmd(ata_channel_t* channel, uint8_t cmd);

#endif
