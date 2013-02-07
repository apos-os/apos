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

#include "dev/block_dev.h"
#include "dev/char_dev.h"

#define DEVICE_MAX_MAJOR 10
#define DEVICE_MAX_MINOR 20

#define DEVICE_ID_UNKNOWN -1

// A device identifier.
typedef struct {
  int major;
  int minor;
} dev_t;

// Register a new block or character device.  The minor id may be
// DEVICE_ID_UNKNOWN, in which case one will be chosen.  The id of the created
// device will be written into the id parameter.  Returns 0 on success, or
// -error.
//
// Block and character devices live in different id namespaces.
int dev_register_block(block_dev_t* dev, dev_t* id);
int dev_register_char(char_dev_t* dev, dev_t* id);

// Retrieve the device with the given id.  Returns NULL if none could be found.
block_dev_t* dev_get_block(dev_t id);
char_dev_t* dev_get_char(dev_t id);

// TODO(aoates): allow removing devices

#endif
