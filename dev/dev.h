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

#ifndef APOO_DEV_DEV_H
#define APOO_DEV_DEV_H

#include <stdint.h>

#include "dev/block_dev.h"
#include "dev/char_dev.h"
#include "memory/memobj.h"
#include "user/include/apos/dev.h"

#define DEVICE_MAX_MAJOR 10
#define DEVICE_MAX_MINOR 20

// Major device types.  Keep this in sync with the device type names in dev.c.
#define DEVICE_MAJOR_ATA 2
#define DEVICE_MAJOR_RAMDISK 3
#define DEVICE_MAJOR_TTY 4
#define DEVICE_MAJOR_NVME 5
#define DEVICE_ID_UNKNOWN UINT16_MAX

_Static_assert(sizeof(apos_dev_t) >= sizeof(uint16_t) * 2,
               "apos_dev_t too small");

// Register a new block or character device.  The minor id may be
// DEVICE_ID_UNKNOWN, in which case one will be chosen.  The id of the created
// device will be written into the id parameter.  Returns 0 on success, or
// -error.
//
// Block and character devices live in different id namespaces.
int dev_register_block(block_dev_t* dev, apos_dev_t* id);
int dev_register_char(char_dev_t* dev, apos_dev_t* id);

// Retrieve the device with the given id.  Returns NULL if none could be found.
block_dev_t* dev_get_block(apos_dev_t id);
char_dev_t* dev_get_char(apos_dev_t id);

// Retrieve the memobj for the block device with the given id.  Returns NULL if
// no such device exists.
memobj_t* dev_get_block_memobj(apos_dev_t id);

// Remove the given block or character device.
//
// NOTE: there may still be outstanding references to the block device.  This
// makes no attempt to synchronize with them.
int dev_unregister_block(apos_dev_t id);
int dev_unregister_char(apos_dev_t id);

// Initialize the /dev filesystem by creating /dev (if it doesn't already
// exist), removing stale entries, and populating with new entries for all
// registered devices.
void dev_init_fs(void);

#endif
