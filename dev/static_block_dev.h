// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

// A simple static data block device with a simple duplicate-block compression
// scheme.
#ifndef APOO_DEV_STATIC_BLOCK_DEV_H
#define APOO_DEV_STATIC_BLOCK_DEV_H

#include <stdint.h>

#include "common/hashtable.h"
#include "dev/block_dev.h"

// Static block size.  128 is picked as a happy medium that minimizes the total
// bytes needed to store an empty ext2 filesystem image.  It also aligns with
// the expected cache line size which should improve multi-block copying
// performance.
#define STATIC_BLOCK_BLKSZ 128

typedef struct {
  uint8_t d[STATIC_BLOCK_BLKSZ];
} stblk_data_single_t;

typedef struct {
  // Block device that can be used to reference this.
  block_dev_t dev;

  // Unique data block contents.  Zero-indexed, and not owned by the static
  // block device.  Generally this is data compiled into the kernel.
  const stblk_data_single_t* block_data;

  // Hash table mapping block index to block_data index.  Any blocks not present
  // in the table are assumed to be all zeroes.
  htbl_t blocks;
} stblk_dev_t;

// Creates a static block device from the given data.
//  * |block_data| is an array of single-block data chunks, one for each unique
//    block of data present in the overall image.
//  * |block_map| is an array of int pairs.  block_map[i] is the index of a
//    block in the image, and block_map[i + 1] is the index of that data in
//    |block_data|.  Any blocks not included will be zeroed.
//  * |block_map_len| is the number of ints in |block_map|.
//  * |total_blocks| is the total number of blocks in the image.
stblk_dev_t* stblk_create(const stblk_data_single_t* block_data,
                          const int* block_map, int block_map_len,
                          int total_blocks);

void stblk_destroy(stblk_dev_t* st);

#endif
