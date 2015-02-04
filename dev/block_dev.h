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

// Interface for block devices.
#ifndef APOO_DEV_BLOCK_DEV_H
#define APOO_DEV_BLOCK_DEV_H

#include <stddef.h>

// A single block device.
struct block_dev {
  int sectors;  // Total number of sectors.
  int sector_size;  // Size in bytes.

  // TODO(aoates): what would it take to allow devices to DMA directly into
  // the given buffers, saving us a copy?

  // Read up to len bytes from the device at a sector offset into the given
  // buffer.  Blocks until the read is complete.  Note that offset is in
  // sectors, not bytes, and len must be an even multiple of the sector size.
  //
  // Returns the number of bytes read on success, or -error on error.
  int (*read)(struct block_dev* dev, size_t offset, void* buf, size_t len,
              int flags);

  // Write up to len bytes to the device at the given sector offset.  Blocks
  // until the write is complete.  Note that offset is in sectors, not bytes,
  // and len must be an even multiple of the sector size.
  //
  // Returns the number of bytes written on success, or -error on error.
  int (*write)(struct block_dev* dev, size_t offset, const void* buf,
               size_t len, int flags);

  // Device-specific private data.
  void* dev_data;
};
typedef struct block_dev block_dev_t;

#endif
