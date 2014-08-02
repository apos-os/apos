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

// A simple in-memory block device.
#ifndef APOO_DEV_RAMDISK_H
#define APOO_DEV_RAMDISK_H

#include <stdint.h>
#include "dev/block_dev.h"

struct ramdisk;
typedef struct ramdisk ramdisk_t;

// Create a ramdisk of the given size (which must be an even multiple of the
// page size).  Returns 0 on success, and sets d to the ramdisk structure.
int ramdisk_create(size_t size, ramdisk_t** d);

// Destroys a ramdisk created with ramdisk_create().
void ramdisk_destroy(ramdisk_t* d);

// Initializes a block_dev_t with data for the given ramdisk.
void ramdisk_dev(ramdisk_t* d, block_dev_t* bd);

// Enable or disable blocking for the ramdisk for reading and/or writing.  If
// enabled, read() and write() calls on the ramdisk will (artificially) yield
// the current thread.
void ramdisk_set_blocking(ramdisk_t* d, int read, int write);

#endif
