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

#include "dev/dev.h"

#include "common/errno.h"
#include "common/kassert.h"

static void* g_block_devices[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR];
static void* g_char_devices[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR];

static int check_register(void* dev, dev_t* id) {
  if (!dev || id->major < 0 || id->major >= DEVICE_MAX_MAJOR ||
      (id->minor < 0 && id->minor != DEVICE_ID_UNKNOWN) ||
      id->minor >= DEVICE_MAX_MINOR) {
    return -EINVAL;
  }
  return 0;
}

// Finds and fills the id, returning 0 on success.
static int find_id(void* array[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR], dev_t* id) {
  if (id->minor != DEVICE_ID_UNKNOWN && array[id->major][id->minor] != 0x0) {
    return -EEXIST;
  } else if (id->minor == DEVICE_ID_UNKNOWN) {
    for (int i = 0; i < DEVICE_MAX_MINOR; ++i) {
      if (array[id->major][i] == 0x0) {
        id->minor = i;
        break;
      }
    }
  }
  KASSERT(array[id->major][id->minor] == 0x0);
  return 0;
}

dev_t mkdev(int major, int minor) {
  dev_t dev;
  dev.major = major;
  dev.minor = minor;
  return dev;
}

int dev_register_block(block_dev_t* dev, dev_t* id) {
  int result = check_register(dev, id);
  if (result) {
    return result;
  }
  result = find_id(g_block_devices, id);
  if (result) {
    return result;
  }

  g_block_devices[id->major][id->minor] = dev;
  return 0;
}

int dev_register_char(char_dev_t* dev, dev_t* id) {
  int result = check_register(dev, id);
  if (result) {
    return result;
  }
  result = find_id(g_char_devices, id);
  if (result) {
    return result;
  }

  g_char_devices[id->major][id->minor] = dev;
  return 0;
}

block_dev_t* dev_get_block(dev_t id) {
  if (id.major < 0 || id.major >= DEVICE_MAX_MAJOR ||
      id.minor < 0 || id.minor >= DEVICE_MAX_MINOR) {
    return 0x0;
  }
  return g_block_devices[id.major][id.minor];
}

char_dev_t* dev_get_char(dev_t id) {
  if (id.major < 0 || id.major >= DEVICE_MAX_MAJOR ||
      id.minor < 0 || id.minor >= DEVICE_MAX_MINOR) {
    return 0x0;
  }
  return g_char_devices[id.major][id.minor];
}

int dev_unregister_block(dev_t id) {
  if (id.major < 0 || id.major >= DEVICE_MAX_MAJOR ||
      id.minor < 0 || id.minor >= DEVICE_MAX_MINOR) {
    return -ERANGE;
  }
  if (g_block_devices[id.major][id.minor] == 0x0) {
    return -ENOENT;
  }
  g_block_devices[id.major][id.minor] = 0x0;
  return 0;
}

int dev_unregister_char(dev_t id) {
  if (id.major < 0 || id.major >= DEVICE_MAX_MAJOR ||
      id.minor < 0 || id.minor >= DEVICE_MAX_MINOR) {
    return -ERANGE;
  }
  if (g_char_devices[id.major][id.minor] == 0x0) {
    return -ENOENT;
  }
  g_char_devices[id.major][id.minor] = 0x0;
  return 0;
}
