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
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "proc/scheduler.h"

struct ramdisk {
  void* data;
  uint32_t size;
  int read_blocking;
  int write_blocking;
};

int ramdisk_create(uint32_t size, ramdisk_t** d) {
  if (size % PAGE_SIZE != 0) {
    return -EINVAL;
  }

  ramdisk_t* disk = (ramdisk_t*)kmalloc(sizeof(ramdisk_t));
  if (!disk) {
    return -ENOMEM;
  }

  disk->data = kmalloc(size);
  if (!disk->data) {
    kfree(disk);
    return -ENOMEM;
  }
  disk->size = size;
  disk->read_blocking = 0;
  disk->write_blocking = 0;
  *d = disk;
  return 0;
}

void ramdisk_destroy(ramdisk_t* d) {
  if (d->data) {
    kfree(d->data);
    d->data = 0x0;
    d->size = 0;
  }
  kfree(d);
}

static int ramdisk_read(struct block_dev* dev, uint32_t offset,
                        void* buf, uint32_t len) {
  if (len % dev->sector_size != 0) {
    return -EINVAL;
  }

  ramdisk_t* d = (ramdisk_t*)dev->dev_data;
  if (offset * dev->sector_size >= d->size) {
    return 0;
  }

  if ((uint32_t)offset * dev->sector_size + len > d->size) {
    len = d->size - (uint32_t)offset * dev->sector_size;
  }

  if (d->read_blocking) {
    scheduler_yield();
  }
  kmemcpy(buf, d->data + offset * dev->sector_size, len);
  return len;
}

static int ramdisk_write(struct block_dev* dev, uint32_t offset,
                         const void* buf, uint32_t len) {
  if (len % dev->sector_size != 0) {
    return -EINVAL;
  }

  ramdisk_t* d = (ramdisk_t*)dev->dev_data;
  if (offset * dev->sector_size >= d->size) {
    return 0;
  }

  if ((uint32_t)offset * dev->sector_size + len > d->size) {
    len = d->size - (uint32_t)offset * dev->sector_size;
  }

  if (d->write_blocking) {
    scheduler_yield();
  }
  kmemcpy(d->data + offset * dev->sector_size, buf, len);
  return len;
}

void ramdisk_dev(ramdisk_t* d, block_dev_t* bd) {
  bd->sectors = d->size / 512;
  bd->sector_size = 512;

  bd->read = &ramdisk_read;
  bd->write = &ramdisk_write;
  bd->dev_data = d;
}

void ramdisk_set_blocking(ramdisk_t* d, int read, int write) {
  d->read_blocking = read;
  d->write_blocking = write;
}
