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

#include "common/errno.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "dev/static_block_dev.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"

static void fill_block(stblk_data_single_t* block, char val) {
  kmemset(block->d, val, STATIC_BLOCK_BLKSZ);
}

void static_block_dev_test(void) {
  KTEST_SUITE_BEGIN("static_block_dev");

  stblk_data_single_t* data = (stblk_data_single_t*)kmalloc(3 * sizeof(stblk_data_single_t));
  fill_block(&data[0], 'A');
  fill_block(&data[1], 'B');
  fill_block(&data[2], 'C');

  // Map:
  // 0 -> data[0] ('A')
  // 1 -> unmapped (zeros)
  // 2 -> data[1] ('B')
  // 3 -> data[0] ('A') (reuse)
  // 4 -> unmapped (zeros)
  // 5 -> data[2] ('C')
  int map[] = {
    0, 0,
    2, 1,
    3, 0,
    5, 2,
  };
  const int TOTAL_BLOCKS = 10;

  const stblk_spec_t kSpec = {.block_data = data,
                              .block_map = map,
                              .block_map_len = 8,
                              .total_blocks = TOTAL_BLOCKS};
  stblk_dev_t* st = stblk_create(&kSpec);
  block_dev_t* dev = &st->dev;

  KTEST_BEGIN("stblk: verify device properties");
  KEXPECT_EQ(TOTAL_BLOCKS, dev->sectors);
  KEXPECT_EQ(STATIC_BLOCK_BLKSZ, dev->sector_size);

  char* buf = (char*)kmalloc(STATIC_BLOCK_BLKSZ * 2);

  KTEST_BEGIN("stblk: read mapped block");
  kmemset(buf, 0, STATIC_BLOCK_BLKSZ);
  KEXPECT_EQ(STATIC_BLOCK_BLKSZ, dev->read(dev, 0, buf, STATIC_BLOCK_BLKSZ, 0));
  for (int i = 0; i < STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ('A', buf[i]);
  }

  KTEST_BEGIN("stblk: read unmapped (zero) block");
  kmemset(buf, 0xFF, STATIC_BLOCK_BLKSZ);
  KEXPECT_EQ(STATIC_BLOCK_BLKSZ, dev->read(dev, 1, buf, STATIC_BLOCK_BLKSZ, 0));
  for (int i = 0; i < STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ(0, buf[i]);
  }

  KTEST_BEGIN("stblk: read reused block");
  kmemset(buf, 0, STATIC_BLOCK_BLKSZ);
  KEXPECT_EQ(STATIC_BLOCK_BLKSZ, dev->read(dev, 3, buf, STATIC_BLOCK_BLKSZ, 0));
  for (int i = 0; i < STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ('A', buf[i]);
  }


  KTEST_BEGIN("stblk: read multiple blocks (mapped + zero)");
  // Read block 0 and 1.
  KEXPECT_EQ(2 * STATIC_BLOCK_BLKSZ, dev->read(dev, 0, buf, 2 * STATIC_BLOCK_BLKSZ, 0));
  for (int i = 0; i < STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ('A', buf[i]);
  }
  for (int i = STATIC_BLOCK_BLKSZ; i < 2 * STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ(0, buf[i]);
  }

  KTEST_BEGIN("stblk: read multiple blocks (zero + mapped)");
  // Read block 1 and 2.
  KEXPECT_EQ(2 * STATIC_BLOCK_BLKSZ, dev->read(dev, 1, buf, 2 * STATIC_BLOCK_BLKSZ, 0));
  for (int i = 0; i < STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ(0, buf[i]);
  }
  for (int i = STATIC_BLOCK_BLKSZ; i < 2 * STATIC_BLOCK_BLKSZ; ++i) {
    KEXPECT_EQ('B', buf[i]);
  }

  KTEST_BEGIN("stblk: write should fail");
  KEXPECT_EQ(-ENXIO, dev->write(dev, 0, buf, STATIC_BLOCK_BLKSZ, 0));
  KEXPECT_EQ(-ENXIO, dev->write(dev, 5, buf, STATIC_BLOCK_BLKSZ, 0));
  KEXPECT_EQ(-ENXIO, dev->write(dev, 0, buf, STATIC_BLOCK_BLKSZ * 2, 0));
  KEXPECT_EQ(-ENXIO, dev->write(dev, 5, buf, STATIC_BLOCK_BLKSZ * 5, 0));
  KEXPECT_EQ(-ENXIO, dev->write(dev, 50, buf, STATIC_BLOCK_BLKSZ, 0));

  stblk_destroy(st);
  kfree(buf);
  kfree(data);
}
