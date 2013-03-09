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

#include "common/kassert.h"
#include "common/io.h"
#include "common/kstring.h"
#include "dev/pci/piix.h"
#include "dev/ata/ata-internal.h"
#include "dev/ata/dma.h"
#include "memory/page_alloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

// Offsets for the busmaster control registers.
#define BM_CMD      0x00
#define BM_STATUS   0x02
#define BM_PRDT     0x04

// Bits in the various registers.
#define BM_CMD_RW          0x08  // 0 = read, 1 = write
#define BM_CMD_STARTSTOP   0x01  // 1 = start, 0 = stop

#define BM_STATUS_D1CAP     0x40
#define BM_STATUS_D2CAP     0x20
// Set if the IDE device has asserted an interrupt.  This is a R/WC bit, so
// write '1' to clear it.
#define BM_STATUS_INTERRUPT 0x04
#define BM_STATUS_ERR       0x02  // Also R/WC
#define BM_STATUS_ACTIVE    0x01  // R/O

// The global PRDT and PRD regions.  These are physical addresses.  Each points
// to a memory region 1 page in size.
// TODO(aoates): we could be much more flexible about this (and allow regions >
// 1 page) for better throughput.  We could also allow callers to get data
// written directly into their buffers.
static uint32_t g_prdt_phys = 0;
static uint32_t g_prd_phys = 0;

// Global lock for the shared DMA buffer.  This keeps us from starting to write
// to the DMA buffer after an operation finished, but before the previous
// operation has had a chance to copy it out.
// TODO(aoates): we should have several DMA buffers and rotate between them to
// reduce contention.
static kmutex_t g_dma_buf_mutex;

// Returns the DMA buffer that should be written to/read from.
static void* dma_get_buffer() {
  KASSERT(g_dma_buf_mutex.locked);
  return (void*)phys2virt(g_prd_phys);
}

static inline uint32_t dma_buffer_size() {
  return PAGE_SIZE;
}

static inline void dma_lock_buffer() {
  kmutex_lock(&g_dma_buf_mutex);
}

static inline void dma_unlock_buffer() {
  kmutex_unlock(&g_dma_buf_mutex);
}

static void dma_setup_transfer(ata_channel_t* channel, uint32_t len,
                               uint8_t is_write) {
  KASSERT(channel->busmaster_offset != 0);
  KASSERT(g_prdt_phys != 0);
  KASSERT(g_prd_phys != 0);
  KASSERT(len <= dma_buffer_size());

  // TODO(aoates): KASSERT no pending DMA transfers?

  uint32_t* prdt = (uint32_t*)phys2virt(g_prdt_phys);
  *prdt = g_prd_phys;
  // This is the last entry.
  *(prdt+1) = 0x80000000 + len;

  // Reset controller.
  outb(channel->busmaster_offset + BM_CMD, 0x0);
  outb(channel->busmaster_offset + BM_STATUS, BM_STATUS_INTERRUPT);
  inb(channel->busmaster_offset + BM_STATUS);
  inb(channel->cmd_offset + 0x07);

  // Set everything up.
  outl(channel->busmaster_offset + BM_PRDT, g_prdt_phys);
  uint8_t cmd = inb(channel->busmaster_offset + BM_CMD);
  // cmd |= 0x60;
  // Note: we set the R/W bit to what the *DMA controller* is doing (i.e.,
  // reading or writing to memory).  So if we're writing to the device, the DMA
  // controller is reading from memory.
  if (is_write) {
    cmd &= ~BM_CMD_RW;
  } else {
    cmd |= BM_CMD_RW;
  }
  KASSERT((cmd & BM_CMD_STARTSTOP) == 0);
  outb(channel->busmaster_offset + BM_CMD, cmd);

  // Clear interrupts and errors.
  uint8_t status = inb(channel->busmaster_offset + BM_STATUS);
  KASSERT((status & BM_STATUS_ACTIVE) == 0);
  status = status | 0x60;
  status = status | BM_STATUS_INTERRUPT | BM_STATUS_ERR;
  outb(channel->busmaster_offset + BM_STATUS, status);
}

static void dma_start_transfer(ata_channel_t* channel) {
  KASSERT(g_dma_buf_mutex.locked);
  KASSERT(channel->busmaster_offset != 0);
  KASSERT(g_prdt_phys != 0);
  KASSERT(g_prd_phys != 0);

  uint8_t cmd = inb(channel->busmaster_offset + BM_CMD);
  cmd |= BM_CMD_STARTSTOP;
  outb(channel->busmaster_offset + BM_CMD, cmd);

  // And we're off!
}

void dma_init() {
  g_prdt_phys = page_frame_alloc();
  // Find a 64-kb aligned page.
  // TODO(aoates): this is a really terrible way of doing this...
  g_prd_phys = page_frame_alloc();
  while (g_prd_phys % 0x10000 != 0) {
    g_prd_phys = page_frame_alloc();
  }
  kmutex_init(&g_dma_buf_mutex);
}

// TODO(aoates): test reading/writing blocks of > 256 sectors (to make sure
// clamping, and in particular the return value, is handled correctly).
void dma_perform_op(ata_disk_op_t* op) {
  KASSERT(op);
  KASSERT(op->drive->channel->pending_op == op);

  // Clamp to DMA buffer size.
  if (op->len > dma_buffer_size()) {
    op->len = dma_buffer_size();
  }

  // Always acquire the DMA lock after acquiring the channel.
  dma_lock_buffer();

  // TODO(aoates): check if DMA has been enabled (if the busmaster driver has
  // loaded) and fail gracefully if so.

  // Select the drive.
  drive_select(op->drive->channel, op->drive->drive_num);

  if (op->is_write) {
    kmemcpy(dma_get_buffer(), op->write_buf, op->len);
  }

  // Start the DMA.
  dma_setup_transfer(op->drive->channel, op->len, op->is_write);

  // Set address and length.
  uint32_t len_sectors = op->len / ATA_BLOCK_SIZE;
  if (len_sectors > 256) {
    len_sectors = 256;
  }
  set_lba(op->drive->channel, op->offset, len_sectors);
  // Send Read or Write DMA command.
  if (op->is_write) {
    send_cmd(op->drive->channel, 0xCA);
  } else {
    send_cmd(op->drive->channel, 0xC8);
  }

  dma_start_transfer(op->drive->channel);
  scheduler_wait_on(&op->waiters);
  KASSERT(op->done != 0);

  op->out_len = len_sectors * ATA_BLOCK_SIZE;
  if (!op->is_write) {
    kmemcpy(op->read_buf, dma_get_buffer(), op->out_len);
  }
  dma_unlock_buffer();
}


void dma_finish_transfer(ata_channel_t* channel) {
  KASSERT(g_dma_buf_mutex.locked);
  KASSERT(channel->busmaster_offset != 0);
  KASSERT(g_prdt_phys != 0);
  KASSERT(g_prd_phys != 0);

  uint8_t cmd = inb(channel->busmaster_offset + BM_CMD);
  cmd &= ~BM_CMD_STARTSTOP;
  outb(channel->busmaster_offset + BM_CMD, cmd);

  // TODO(aoates): check error status, reset interrupt line, etc.
}
