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

#include "common/errno.h"
#include "common/math.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "memory/block_cache.h"
#include "memory/memobj.h"
#include "vfs/special.h"
#include "vfs/vnode.h"

static int block_dev_op(int is_write, apos_dev_t dev, int offset,
                        void* buf, int len) {
  memobj_t* obj = dev_get_block_memobj(dev);
  if (!obj) {
    return -ENXIO;
  }

  int bytes_read = 0;
  while (bytes_read < len) {
    // TODO(aoates): check against length of block device.
    const addr_t page_idx = (offset + bytes_read) / PAGE_SIZE;
    const addr_t page_offset = (offset + bytes_read) % PAGE_SIZE;
    bc_entry_t* entry = 0x0;
    const int result = block_cache_get(obj, page_idx, &entry);
    if (result) return result;

    const unsigned int chunk_bytes =
        min((unsigned int)len - bytes_read, PAGE_SIZE - page_offset);
    if (is_write) {
      kmemcpy((char*)entry->block + page_offset,
              (const char*)buf + bytes_read, chunk_bytes);
      block_cache_put(entry, BC_FLUSH_SYNC);
    } else {
      kmemcpy((char*)buf + bytes_read,
              (const char*)entry->block + page_offset, chunk_bytes);
      block_cache_put(entry, BC_FLUSH_NONE);
    }
    bytes_read += chunk_bytes;
  }

  return bytes_read;
}

int special_device_read(vnode_type_t type, apos_dev_t dev, int offset,
                        void* buf, int len) {
  KASSERT(type == VNODE_BLOCKDEV || type == VNODE_CHARDEV);
  if (type == VNODE_BLOCKDEV) {
    return block_dev_op(0, dev, offset, buf, len);
  } else {
    KASSERT(offset == 0);  // Can't seek in character devices.
    char_dev_t* chardev = dev_get_char(dev);
    if (!chardev) return -ENXIO;
    return chardev->read(chardev, buf, len);
  }
}

int special_device_write(vnode_type_t type, apos_dev_t dev, int offset,
                         const void* buf, int len) {
  KASSERT(type == VNODE_BLOCKDEV || type == VNODE_CHARDEV);
  if (type == VNODE_BLOCKDEV) {
    return block_dev_op(1, dev, offset, (void*)buf, len);
  } else {
    KASSERT(offset == 0);  // Can't seek in character devices.
    char_dev_t* chardev = dev_get_char(dev);
    if (!chardev) return -ENXIO;
    return chardev->write(chardev, buf, len);
  }
}
