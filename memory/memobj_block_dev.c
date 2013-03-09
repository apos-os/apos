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
#include "common/errno.h"
#include "common/hash.h"
#include "common/kstring.h"
#include "dev/dev.h"
#include "dev/block_dev.h"
#include "memory/memobj_block_dev.h"
#include "memory/memobj.h"
#include "memory/memory.h"

static int bd_read_page(memobj_t* obj, int offset, void* buffer);
static int bd_write_page(memobj_t* obj, int offset, const void* buffer);

static memobj_ops_t g_block_dev_ops = {
  &bd_read_page,
  &bd_write_page,
};

static int bd_read_page(memobj_t* obj, int offset, void* buffer) {
  KASSERT(obj->type == MEMOBJ_BLOCK_DEV);
  KASSERT(obj->data != 0x0);

  block_dev_t* bd = (block_dev_t*)obj->data;
  const int kSectorsPerPage = PAGE_SIZE / bd->sector_size;
  // TODO(aoates): handle the last few sectors of a device if it's not an even
  // multiple of the page size.
  if (offset < 0 || (offset + 1) * kSectorsPerPage > bd->sectors) {
    return -ERANGE;
  }

  int result = bd->read(bd, offset * kSectorsPerPage, buffer, PAGE_SIZE);
  if (result < 0) return result;

  // TODO(aoates): handle partial reads more gracefully.
  KASSERT(result == PAGE_SIZE);
  return 0;
}

static int bd_write_page(memobj_t* obj, int offset, const void* buffer) {
  KASSERT(obj->type == MEMOBJ_BLOCK_DEV);
  KASSERT(obj->data != 0x0);

  block_dev_t* bd = (block_dev_t*)obj->data;
  const int kSectorsPerPage = PAGE_SIZE / bd->sector_size;
  // TODO(aoates): handle the last few sectors of a device if it's not an even
  // multiple of the page size.
  if (offset < 0 || (offset + 1) * kSectorsPerPage > bd->sectors) {
    return -ERANGE;
  }

  int result = bd->write(bd, offset * kSectorsPerPage, buffer, PAGE_SIZE);
  if (result < 0) return result;

  // TODO(aoates): handle partial writes more gracefully.
  KASSERT(result == PAGE_SIZE);
  return 0;
}

int memobj_create_block_dev(memobj_t* obj, dev_t dev) {
  kmemset(obj, 0, sizeof(memobj_t));
  obj->type = MEMOBJ_BLOCK_DEV;
  obj->id = fnv_hash_array(&dev, sizeof(dev_t));
  obj->data = dev_get_block(dev);
  if (!obj->data) {
    return -ENODEV;
  }

  obj->ops = &g_block_dev_ops;
  return 0;
}
