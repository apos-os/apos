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

#include "common/klog.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/io.h"
#include "dev/ata/ata.h"

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

#define ATA_DRIVE_MASTER 0
#define ATA_DRIVE_SLAVE  1
#define ATA_BLOCK_SIZE 512

// Data about a particular drive.
struct drive {
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

  // TODO(aoates): the rest of the fields.
};
typedef struct drive drive_t;

static ata_t g_ata;
static int g_init = 0;

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

// Issues an ATA command then reads a block of data in blocking PIO mode.
// Assumes that any needed parameters (including the drive select!) have already
// been loaded into the appropriate registers.  Returns 0 on success.
//
// This involves a busy looping waiting for data, so really shouldn't be used
// except at boot time.
//
// TODO(aoates): make this work for commands that read more than one block of
// data.
static int pio_read_block(ata_channel_t* channel, uint8_t cmd, uint16_t* buf) {
  // Wait until BSY is unset.
  wait_until_clear(channel, ATA_STATUS_BSY);

  // Send the command, the wait until BSY is unset again.
  outb(channel->cmd_offset + ATA_CMD_CMD, cmd);
  wait_until_clear(channel, ATA_STATUS_BSY);

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
// TODO(aoates): this needs to select a portion of the LBA too!
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

  if (pio_read_block(channel, CMD, buf)) {
    klogf("ata: error reading data from 'identify drive' command\n");
    return -2;
  }

  // Check some of the 'required 0' words to make sure everything looks OK.
  if (buf[2] != 0 || buf[7] != 0 || buf[8] != 0 ||
      buf[9] != 0 || buf[50] != 0) {
    klogf("ata: bad data in response to identify drive command\n");
    return -3;
  }

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

  return 0;
}

void ata_init(const ata_t* ata) {
  KASSERT(g_init == 0);
  g_ata = *ata;
  g_init = 1;

  klogf("ATA: scanning for ATA drives...\n");
  // Identify all the drives available.
  drive_t drives[4];
  int drives_status[4];

  drives_status[0] = identify_drive(&g_ata.primary,
                                    ATA_DRIVE_MASTER, &drives[0]);
  drives_status[1] = identify_drive(&g_ata.primary,
                                    ATA_DRIVE_SLAVE, &drives[1]);
  drives_status[2] = identify_drive(&g_ata.secondary,
                                    ATA_DRIVE_MASTER, &drives[2]);
  drives_status[3] = identify_drive(&g_ata.secondary,
                                    ATA_DRIVE_SLAVE, &drives[3]);

  for (int i = 0; i < 4; ++i) {
    if (drives_status[i] == 0) {
      uint32_t total_size = drives[i].cylinders * drives[i].heads *
          drives[i].sectors_per_track * drives[i].bytes_per_sector;
      klogf("  ATA drive %d: %s (%s) --- %dc/%dh/%ds (%d bytes/sector) -- %d (%d MB) total\n", i,
            drives[i].model, drives[i].serial, drives[i].cylinders, drives[i].heads,
            drives[i].sectors_per_track, drives[i].bytes_per_sector, total_size,
            total_size / 1000000);
    }
  }

  // TODO(aoates): enable interrupts with device control register
}
