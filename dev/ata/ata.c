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

#include <stdint.h>

#include "common/errno.h"
#include "common/klog.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/io.h"
#include "dev/ata/ata.h"
#include "dev/ata/ata-internal.h"
#include "dev/ata/queue.h"
#include "dev/irq.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

static ata_t g_ata;
static int g_init = 0;

// Port offsets (from the base ports given in the ata_t structure) for the ATA
// control registers.  Some registers have different purposes when reading vs.
// writing, and are enumerated twice.
#define ATA_CMD_DATA        0x00  // R/W
#define ATA_CMD_ERROR       0x01  // When reading.
#define ATA_CMD_FEATURES    0x01  // When writing.
#define ATA_CMD_SECTOR_CNT  0x02  // R/W
#define ATA_CMD_SECTOR_NUM  0x03  // R/W
#define ATA_CMD_CYL_LOW     0x04  // R/W
#define ATA_CMD_CYL_HIGH    0x05  // R/W
#define ATA_CMD_DRIVE_HEAD  0x06  // R/W
#define ATA_CMD_STATUS      0x07  // When reading.
#define ATA_CMD_CMD         0x07  // When writing.

#define ATA_CTRL_ALT_STATUS 0x06  // When reading.
#define ATA_CTRL_DEV_CTRL   0x06  // When writing.

// Bits in the status/alt status registers.
#define ATA_STATUS_BSY  0x80
#define ATA_STATUS_DRQ  0x08
#define ATA_STATUS_ERR  0x01

// Bits in the drive/head register
#define ATA_DH_LBA 0x40  // Selects LBA mode.
#define ATA_DH_DRV 0x10  // 0 for master, 1 for slave.
#define ATA_HD_HEAD_MASK 0x0F

// Feature bits in the features2 field of the drive info.
#define ATA_FEAT2_LBA 0x200
#define ATA_FEAT2_DMA 0x100

// Reads the status register on the given channel.  This resets the interrupt
// state.
static inline uint8_t read_status(ata_channel_t* channel) {
  return inb(channel->cmd_offset + ATA_CMD_STATUS);
}

// Same as above, but reads without resetting the interrupt state
static inline uint8_t read_alt_status(ata_channel_t* channel) {
  return inb(channel->ctrl_offset + ATA_CTRL_ALT_STATUS);
}

// Waits until ALL the given bits in the (alternate) status register are clear.
static inline void wait_until_clear(ata_channel_t* channel, uint8_t bits) {
  uint8_t status = read_alt_status(channel);
  while ((status & bits) != 0) {
    status = read_alt_status(channel);
  }
}

// Waits until ANY OF the given bits in the (alternate) status register are set.
static inline void wait_until_set(ata_channel_t* channel, uint8_t bits) {
  uint8_t status = read_alt_status(channel);
  while ((status & bits) == 0) {
    status = read_alt_status(channel);
  }
}

// Issues an ATA command on the given channel, blocking until the BSY flag is
// clear before sending it.  Assumes that any needed parameters (including the
// drive select!) have already been loaded into the appropriate registers.
static void send_cmd(ata_channel_t* channel, uint8_t cmd) {
  // Wait until BSY is unset.
  wait_until_clear(channel, ATA_STATUS_BSY);

  // Send the command, the wait until BSY is unset again.
  outb(channel->cmd_offset + ATA_CMD_CMD, cmd);
}

// Blocks until BSY is unset, then reads a block of data in blocking PIO mode.
// Returns 0 on success.
//
// This involves a busy looping waiting for data, so really shouldn't be used
// except at boot time.
static int pio_read_block(ata_channel_t* channel, uint16_t* buf) {
  // Wait for DRQ or ERR to be set
  // TODO(aoates): have a timeout here.  Also check for write faults?
  wait_until_set(channel, ATA_STATUS_DRQ | ATA_STATUS_ERR);
  uint8_t status = read_status(channel);
  if (status & ATA_STATUS_ERR) {
    return -1;
  }

  KASSERT(status & ATA_STATUS_DRQ);  // Data must be ready!

  for (int i = 0; i < ATA_BLOCK_SIZE / 2; ++i) {
    buf[i] = ins(channel->cmd_offset + ATA_CMD_DATA);
  }
  return 0;
}

// Select a drive (ATA_DRIVE_MASTER or ATA_DRIVE_SLAVE) on the given channel.
static inline void drive_select(ata_channel_t* channel, uint8_t drive) {
  KASSERT(drive == 0 || drive == 1);
  const uint8_t dh = 0xA0 | ATA_DH_LBA | (drive * ATA_DH_DRV);
  outb(channel->cmd_offset + ATA_CMD_DRIVE_HEAD, dh);
  // Read the status register 5 times to let it stabilize.
  // TODO(aoates): only do this when switching drives.
  read_status(channel);
  read_status(channel);
  read_status(channel);
  read_status(channel);
}

// Load the given LBA address into the appropriate registers.
static inline void set_lba(ata_channel_t* channel, uint32_t lba) {
  KASSERT((lba & 0xF0000000) == 0);  // Must be 28-bit.

  // Load bits 27-24 into the DH register.
  uint8_t dh = inb(channel->cmd_offset + ATA_CMD_DRIVE_HEAD);
  dh = (dh & 0xF0) | ATA_DH_LBA | ((lba >> 24) & 0x0000000F);
  outb(channel->cmd_offset + ATA_CMD_DRIVE_HEAD, dh);

  // Bits 23-16 go in the cylinder high register.
  outb(channel->cmd_offset + ATA_CMD_CYL_HIGH,
       (lba >> 16) & 0x000000FF);

  // Bits 15-8 go in the cylinder low register.
  outb(channel->cmd_offset + ATA_CMD_CYL_LOW,
       (lba >> 8) & 0x000000FF);

  // Bits 7-0 go in the sector number register.
  outb(channel->cmd_offset + ATA_CMD_SECTOR_NUM, lba & 0x000000FF);
}

// When strings are read by the IDENTIFY command in 2-byte chunks, the byte
// order gets reversed.  This cleans up the strings.
static void cleanup_ata_string(char* s, int len) {
  // Swap characters.
  int i = 0;
  while (i < len - 1) {
    char tmp = s[i];
    s[i] = s[i+1];
    s[i+1] = tmp;
    i += 2;
  }

  // Trim trailing spaces.
  i = len - 2;
  while (i > 0 && s[i] == ' ') {
    s[i] = '\0';
    i--;
  }
}

// Send the "identify drive" command for the given channel and drive.  Returns 0
// if successful (meaning a drive was found and the identify command was
// successful).  Returns non-zero if there was no drive or there was an error.
static int identify_drive(ata_channel_t* channel, uint8_t drive, drive_t* d) {
  const uint8_t CMD = 0xEC;
  uint16_t buf[ATA_BLOCK_SIZE];

  // Check for floating status.
  uint8_t status = read_status(channel);
  if (status == 0xFF) {
    klogf("ata: floating status (no drives) on channel\n");
    return -1;
  }

  drive_select(channel, drive);
  // Check if the drive exists.
  status = read_status(channel);
  if (status == 0x00) {
    return -1;
  }

  send_cmd(channel, CMD);
  if (pio_read_block(channel, buf)) {
    klogf("ata: error reading data from 'identify drive' command\n");
    return -2;
  }

  // Check some of the 'required 0' words to make sure everything looks OK.
  if (buf[2] != 0 || buf[7] != 0 || buf[8] != 0 ||
      buf[9] != 0 || buf[50] != 0) {
    klogf("ata: bad data in response to identify drive command\n");
    return -3;
  }

  d->channel = channel;
  d->drive_num = drive;

  d->features = buf[0];
  d->cylinders = buf[1];
  d->heads = buf[3];
  d->bytes_per_track = buf[4];
  d->bytes_per_sector = buf[5];
  d->sectors_per_track = buf[6];
  kmemcpy(d->serial, &buf[10], 20);
  d->serial[20] = '\0';
  cleanup_ata_string(d->serial, 20);

  d->buf_type = buf[20];
  d->buf_size = buf[21];
  d->ecc_bytes = buf[22];

  kmemcpy(d->firmware, &buf[23], 8);
  d->firmware[8] = '\0';
  cleanup_ata_string(d->firmware, 8);

  kmemcpy(d->model, &buf[27], 40);
  d->model[40] = '\0';
  cleanup_ata_string(d->model, 40);

  d->features2 = buf[49];
  d->lba_sectors = ((buf[61] << 16) & 0xFFFF0000) +
      (buf[60] & 0x0000FFFF);

  return 0;
}

static void ata_dump_state(ata_channel_t* channel) {
  klogf(" ATA_CMD_DATA: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_DATA));
  klogf(" ATA_CMD_ERROR: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_ERROR));
  klogf(" ATA_CMD_SECTOR_CNT: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_SECTOR_CNT));
  klogf(" ATA_CMD_SECTOR_NUM: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_SECTOR_NUM));
  klogf(" ATA_CMD_CYL_LOW: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_CYL_LOW));
  klogf(" ATA_CMD_CYL_HIGH: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_CYL_HIGH));
  klogf(" ATA_CMD_DRIVE_HEAD: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_DRIVE_HEAD));
  klogf(" ATA_CMD_STATUS: 0x%x\n", inb(channel->cmd_offset + ATA_CMD_STATUS));
}

static kthread_queue_t g_wait_queue;
// IRQ handlers for the primary and secondary channels.
static void irq_handler_primary() {
  klogf("IRQ for primary ATA device\n");
  ata_channel_t* channel = &g_ata.primary;
  dma_finish_transfer(channel);
  uint8_t status = inb(channel->busmaster_offset + 0x02);
  klogf("  controller status: 0x%x\n", status);
  status = inb(channel->cmd_offset + ATA_CMD_STATUS);
  klogf("  device status: 0x%x\n", status);
  status = inb(channel->cmd_offset + ATA_CMD_ERROR);
  klogf("  device error: 0x%x\n", status);
  ata_dump_state(channel);

  kthread_t t = kthread_queue_pop(&g_wait_queue);
  while (t) {
    scheduler_make_runnable(t);
    t = kthread_queue_pop(&g_wait_queue);
  }
}

static void irq_handler_secondary() {
  klogf("IRQ for secondary ATA device\n");
}

static void ata_do_op(ata_disk_op_t* op) {
  op->status = 0;
  op->out_len = 0;

  // TODO(aoates): we need to deal with locking the channel, waiting for pending
  // reads, etc.
  if (op->len % ATA_BLOCK_SIZE != 0) {
    op->status = -EINVAL;
    return;
  }

  if (op->offset >= op->drive->lba_sectors) {
    return;  // Nothing to do.
  }

  uint32_t len = op->len;
  if (op->offset + (len / ATA_BLOCK_SIZE) > op->drive->lba_sectors) {
    len = (op->drive->lba_sectors - op->offset) * ATA_BLOCK_SIZE;
  }

  if (len == 0) {
    return;
  }

  // TODO(aoates) this is a silly cap.
  // KASSERT(len <= PAGE_SIZE);

  // TODO(aoates): check if DMA has been enabled (if the busmaster driver has
  // loaded) and fail gracefully if so.

  // TODO(aoates): check if the channel is active!
  // Select the drive.
  drive_select(op->drive->channel, op->drive->drive_num);

  if (op->is_write) {
    kmemcpy(dma_get_buffer(), op->write_buf, len);
  }

  // Start the DMA.
  dma_setup_transfer(op->drive->channel, len, op->is_write);

  // Set address and length.
  uint32_t len_sectors = len / ATA_BLOCK_SIZE;
  if (len_sectors > 255) {
    len_sectors = 255;
  } else if (len_sectors == 256) {
    len_sectors = 0;
  }
  set_lba(op->drive->channel, op->offset);
  outb(op->drive->channel->cmd_offset + ATA_CMD_SECTOR_CNT, len_sectors);
  // Send Read or Write DMA command.
  if (op->is_write) {
    send_cmd(op->drive->channel, 0xCA);
  } else {
    send_cmd(op->drive->channel, 0xC8);
  }

  ata_dump_state(op->drive->channel);

  dma_start_transfer(op->drive->channel);

  scheduler_wait_on(&g_wait_queue);

  if (!op->is_write) {
    kmemcpy(op->read_buf, dma_get_buffer(), len);
  }

  op->out_len = len;
}

static int ata_read(struct block_dev* dev, uint32_t offset,
                    void* buf, uint32_t len) {
  ata_disk_op_t op;
  op.drive = (drive_t*)dev->dev_data;
  op.is_write = 0;
  op.offset = offset;
  op.read_buf = buf;
  op.write_buf = 0x0;
  op.len = len;
  ata_do_op(&op);

  if (op.status < 0) {
    return op.status;
  } else {
    return op.out_len;
  }
}

static int ata_write(struct block_dev* dev, uint32_t offset,
                     const void* buf, uint32_t len) {
  ata_disk_op_t op;
  op.drive = (drive_t*)dev->dev_data;
  op.is_write = 1;
  op.offset = offset;
  op.read_buf = 0x0;
  op.write_buf = buf;
  op.len = len;
  ata_do_op(&op);

  if (op.status < 0) {
    return op.status;
  } else {
    return op.out_len;
  }
}

static void create_ata_block_dev(drive_t* d, block_dev_t* bd) {
  KASSERT(d->present);
  KASSERT(d->supported);

  kmemset(bd, 0, sizeof(block_dev_t));
  bd->sectors = d->lba_sectors;
  bd->sector_size = ATA_BLOCK_SIZE;
  bd->dev_data = d;

  bd->read = &ata_read;
  bd->write = &ata_write;
}

// A global array of drives, one for each possible device.  Not all will be
// present or supported.
#define ATA_MAX_DRIVES 4
static drive_t g_drives[ATA_MAX_DRIVES];

// An array of block_dev_ts, one for each present and supported device.  At
// init-time, after detecting drives, we go through each potential device and
// create a block_dev_t here for it if it's supported.
static block_dev_t g_ata_block_devs[ATA_MAX_DRIVES];
static int g_num_ata_block_devs = 0;

static void ata_init_internal(const ata_t* ata) {
  KASSERT(g_init == 0);
  g_ata = *ata;
  g_init = 1;
  kthread_queue_init(&g_wait_queue);

  klogf("ATA: scanning for ATA drives...\n");
  // Identify all the drives available.
  int drives_status[ATA_MAX_DRIVES];

  drives_status[0] = identify_drive(&g_ata.primary,
                                    ATA_DRIVE_MASTER, &g_drives[0]);
  drives_status[1] = identify_drive(&g_ata.primary,
                                    ATA_DRIVE_SLAVE, &g_drives[1]);
  drives_status[2] = identify_drive(&g_ata.secondary,
                                    ATA_DRIVE_MASTER, &g_drives[2]);
  drives_status[3] = identify_drive(&g_ata.secondary,
                                    ATA_DRIVE_SLAVE, &g_drives[3]);

  for (int i = 0; i < ATA_MAX_DRIVES; ++i) {
    if (drives_status[i] == 0) {
      g_drives[i].present = 1;

      // We require support for LBA and DMA.
      if ((g_drives[i].features2 & ATA_FEAT2_LBA) == 0 ||
          (g_drives[i].features2 & ATA_FEAT2_DMA) == 0) {
        klogf("ata: found drive %d, but doesn't support LBA or DMA :(\n", i);
        g_drives[i].supported = 0;
      } else {
        g_drives[i].supported = 1;
      }
    } else {
      g_drives[i].present = 0;
      g_drives[i].supported = 0;
    }
  }

  // Create block devices for (and log about) each device we found.
  for (int i = 0; i < ATA_MAX_DRIVES; ++i) {
    if (g_drives[i].present && g_drives[i].supported) {
      uint32_t total_size =
          g_drives[i].lba_sectors * g_drives[i].bytes_per_sector;
      klogf("  ATA drive %d: %s (%s) --- %dc/%dh/%ds (%d bytes/sector) "
            "-- %d (%d MB) total\n", i,
            g_drives[i].model, g_drives[i].serial, g_drives[i].cylinders,
            g_drives[i].heads, g_drives[i].sectors_per_track,
            g_drives[i].bytes_per_sector, total_size, total_size / 1000000);
      create_ata_block_dev(&g_drives[i],
                           &g_ata_block_devs[g_num_ata_block_devs]);
      g_num_ata_block_devs++;
    }
  }

  // Initialize DMA stuff.
  dma_init();

  // Set up IRQs.
  register_irq_handler(g_ata.primary.irq, &irq_handler_primary);
  register_irq_handler(g_ata.secondary.irq, &irq_handler_secondary);

  // TODO(aoates): enable interrupts with device control register
}

// TODO(aoates): if we have global ata_channel_t's, we sholud just set them
// directly.
static uint16_t g_busmaster_prim_offset = 0;
static uint16_t g_busmaster_secd_offset = 0;
void ata_enable_bumaster(uint16_t primary_offset, uint16_t secondary_offset) {
  g_busmaster_prim_offset = primary_offset;
  g_busmaster_secd_offset = secondary_offset;
}

void ata_init() {
  // Initialize the ATA driver with the I/O port ranges used by the PIIX(3) (see
  // page 96 of the datasheet).  There doesn't seem to be a way to determine
  // these dynamically, so we just guess-and-pray.
  ata_t ata;
  ata.primary.cmd_offset =  0x01F0;
  ata.primary.ctrl_offset = 0x03F0;
  ata.primary.busmaster_offset = g_busmaster_prim_offset;
  ata.primary.irq = 14;
  ata.secondary.cmd_offset =  0x0170;
  ata.secondary.ctrl_offset = 0x0370;
  ata.secondary.busmaster_offset = g_busmaster_secd_offset;
  ata.secondary.irq = 15;

  // TODO(aoates): Sometimes we could have 4 ATA channels -- try to
  // initialize all 4.

  ata_init_internal(&ata);
}

int ata_num_devices() {
  return g_num_ata_block_devs;
}

block_dev_t* ata_get_block_dev(int dev) {
  if (dev < 0 || dev >= g_num_ata_block_devs) {
    return 0x0;
  }
  return &g_ata_block_devs[dev];
}
