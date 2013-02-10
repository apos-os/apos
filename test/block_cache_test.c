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
#include "dev/block_cache.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory.h"
#include "test/ktest.h"

#define RAMDISK_SIZE (PAGE_SIZE * 4)
#define RAMDISK_BLOCKS (RAMDISK_SIZE / BLOCK_CACHE_BLOCK_SIZE)

#define RAMDISK_SECTOR_SIZE 512

static int block2sector(block_dev_t* bd, int block) {
  return block * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
}

static void setup_disk(dev_t dev) {
  block_dev_t* bd = dev_get_block(dev);

  char data[BLOCK_CACHE_BLOCK_SIZE];
  kmemset(data, 0, BLOCK_CACHE_BLOCK_SIZE);
  for (int i = 0; i < RAMDISK_BLOCKS; ++i) {
    kmemset(data, 0, 20);
    ksprintf(data, "block%i", i);
    ksprintf(&data[BLOCK_CACHE_BLOCK_SIZE - 10], "end%i", i);
    const int sector_offset = block2sector(bd, i);
    KASSERT(BLOCK_CACHE_BLOCK_SIZE ==
            bd->write(bd, sector_offset, data, BLOCK_CACHE_BLOCK_SIZE));
  }
}

static void basic_get_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): basic test");
  setup_disk(dev);

  for (int i = 0; i < RAMDISK_BLOCKS; ++i) {
    void* block = block_cache_get(dev, i);
    KEXPECT_NE(0x0, (int)block);

    char data[100];
    ksprintf(data, "block%i", i);
    KEXPECT_STREQ(data, block);

    ksprintf(data, "end%i", i);
    KEXPECT_STREQ(data, block + BLOCK_CACHE_BLOCK_SIZE - 10);
    block_cache_put(dev, i);
  }

  KTEST_BEGIN("block_cache_get(): same pointer returned");
  void* block0a = block_cache_get(dev, 0);
  void* block0b = block_cache_get(dev, 0);
  void* block1 = block_cache_get(dev, 1);
  KEXPECT_EQ((int)block0a, (int)block0b);
  KEXPECT_NE((int)block0a, (int)block1);
  block_cache_put(dev, 0);
  block_cache_put(dev, 0);
  block_cache_put(dev, 1);
}

// TODO(aoates): test write at end
// TODO(aoates): test multi-threaded get() calls for same block.
// TODO(aoates): test running out of space on the free block stack
// TODO(aoates): test multi-threaded get()/put() to make sure that if we get()
// during a (final) put() call, we don't read old data.

static void basic_write_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): basic write/put test");
  setup_disk(dev);

  void* block = block_cache_get(dev, 1);
  kstrcpy(block, "written block");
  block_cache_put(dev, 1);

  // Verify that it was written back to the ramdisk.
  char buf[RAMDISK_SECTOR_SIZE];
  block_dev_t* bd = dev_get_block(dev);
  KASSERT(RAMDISK_SECTOR_SIZE ==
          bd->read(bd, block2sector(bd, 1), buf, RAMDISK_SECTOR_SIZE));
  KEXPECT_EQ(0, kstrcmp(buf, "written block"));

  // Write to the raw disk.
  kstrcpy(buf, "WRITTEN BLOCK");
  KASSERT(BLOCK_CACHE_BLOCK_SIZE ==
          bd->write(bd, block2sector(bd, 1), buf, BLOCK_CACHE_BLOCK_SIZE));

  // Verify that if we get() it again we see the new data.
  block = block_cache_get(dev, 1);
  KEXPECT_EQ(0, kstrcmp(block, "WRITTEN BLOCK"));
  block_cache_put(dev, 1);
}

static void get_shares_buffers_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): get shares buffers");
  setup_disk(dev);

  // Note: it's a little silly to use 2 pointers, since they should be equal
  // anyways.
  void* blockA = block_cache_get(dev, 3);
  void* blockB = block_cache_get(dev, 3);

  // Write to the first buffer, then put() it.
  kstrcpy(blockA, "written to A");
  block_cache_put(dev, 3);

  // Make sure we can still read it out of the second buffer.
  KEXPECT_EQ(0, kstrcmp(blockB, "written to A"));
  block_cache_put(dev, 3);
}

static void cache_size_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): cache size");
  setup_disk(dev);
  block_cache_set_size(3);

  void* block0a = block_cache_get(dev, 0);
  void* block0b = block_cache_get(dev, 0);
  void* block1 = block_cache_get(dev, 1);
  void* block2 = block_cache_get(dev, 2);
  void* block3 = block_cache_get(dev, 3);
  KEXPECT_NE(0x0, (int)block0a);
  KEXPECT_NE(0x0, (int)block0b);
  KEXPECT_NE(0x0, (int)block1);
  KEXPECT_NE(0x0, (int)block2);
  KEXPECT_EQ(0x0, (int)block3);

  // Put back one of the refs to the first block and make sure we still can't
  // get a new block.
  block_cache_put(dev, 0);
  block3 = block_cache_get(dev, 3);
  KEXPECT_EQ(0x0, (int)block3);

  // Put back the other ref, then make sure we can get the third block.
  block_cache_put(dev, 0);
  block3 = block_cache_get(dev, 3);
  KEXPECT_NE(0x0, (int)block3);

  // Clean up.
  block_cache_put(dev, 1);
  block_cache_put(dev, 2);
  block_cache_put(dev, 3);
}

void block_cache_test() {
  KTEST_SUITE_BEGIN("block_cache test");

  // Set up a ramdisk to use for testing.
  ramdisk_t* ramdisk = 0x0;
  block_dev_t ramdisk_bd;
  KASSERT(ramdisk_create(RAMDISK_SIZE, &ramdisk) == 0);
  ramdisk_dev(ramdisk, &ramdisk_bd);

  dev_t dev = mkdev(DEVICE_MAJOR_RAMDISK, DEVICE_ID_UNKNOWN);
  KASSERT(dev_register_block(&ramdisk_bd, &dev) == 0);

  // Run tests.
  basic_get_test(dev);
  basic_write_test(dev);
  get_shares_buffers_test(dev);
  cache_size_test(dev);

  // Cleanup.
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);
}
