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
#include "memory/block_cache.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/memory.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "test/ktest.h"

// TODO(aoates): rewrite this test to use a custom memobj so we don't have to
// use a ramdisk.

#define RAMDISK_SIZE (PAGE_SIZE * 4)
#define RAMDISK_BLOCKS (RAMDISK_SIZE / BLOCK_CACHE_BLOCK_SIZE)

#define RAMDISK_SECTOR_SIZE 512

static int block2sector(block_dev_t* bd, int block) {
  return block * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
}

static void setup_disk(dev_t dev) {
  block_cache_clear_unpinned();
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

  memobj_t* obj = dev_get_block_memobj(dev);
  for (int i = 0; i < RAMDISK_BLOCKS; ++i) {
    bc_entry_t* block = 0x0;
    KEXPECT_EQ(0, block_cache_get(obj, i, &block));
    KEXPECT_NE(0x0, (int)block);
    KEXPECT_EQ(virt2phys((uint32_t)block->block), block->block_phys);

    char data[100];
    ksprintf(data, "block%i", i);
    KEXPECT_STREQ(data, block->block);

    ksprintf(data, "end%i", i);
    KEXPECT_STREQ(data, block->block + BLOCK_CACHE_BLOCK_SIZE - 10);
    block_cache_put(block, BC_FLUSH_SYNC);
  }

  KTEST_BEGIN("block_cache_get(): same pointer returned");
  bc_entry_t *block0a, *block0b, *block1;
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0a));
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0b));
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block1));
  KEXPECT_EQ((int)block0a, (int)block0b);
  KEXPECT_NE((int)block0a, (int)block1);
  block_cache_put(block0a, BC_FLUSH_SYNC);
  block_cache_put(block0b, BC_FLUSH_SYNC);
  block_cache_put(block1, BC_FLUSH_SYNC);
}

static void basic_lookup_test(dev_t dev) {
  KTEST_BEGIN("block_cache_lookup(): basic test");
  setup_disk(dev);

  memobj_t* obj = dev_get_block_memobj(dev);

  bc_entry_t* block = (bc_entry_t*)0xABCD;
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(0x0, (uint32_t)block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(0x0, (uint32_t)block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 1, &block));
  KEXPECT_EQ(0x0, (uint32_t)block);

  // Now get() the block.
  bc_entry_t* get_block = (bc_entry_t*)0xABCD;
  KEXPECT_EQ(0, block_cache_get(obj, 0, &get_block));
  KEXPECT_NE(0x0, (uint32_t)get_block);

  // ..and make sure we can get it via lookup now.
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(get_block, block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(get_block, block);

  KEXPECT_EQ(3, block_cache_get_pin_count(obj, 0));

  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(obj, 0));
}

// TODO(aoates): test running out of space on the free block stack

static void basic_write_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): basic write/put test");
  setup_disk(dev);
  memobj_t* obj = dev_get_block_memobj(dev);

  bc_entry_t* block = 0x0;
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  kstrcpy(block->block, "written block");
  block_cache_put(block, BC_FLUSH_SYNC);

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
  block_cache_clear_unpinned();
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  KEXPECT_EQ(0, kstrcmp(block->block, "WRITTEN BLOCK"));
  block_cache_put(block, BC_FLUSH_SYNC);
}

static void write_at_end_test(dev_t dev) {
  KTEST_BEGIN("block_cache_put(): write at end of block");
  memobj_t* obj = dev_get_block_memobj(dev);

  bc_entry_t* block;
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  kstrcpy(block->block + BLOCK_CACHE_BLOCK_SIZE - 20, "written end");
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));

  // Verify that it was written back to the ramdisk.
  char buf[BLOCK_CACHE_BLOCK_SIZE];
  block_dev_t* bd = dev_get_block(dev);
  KASSERT(BLOCK_CACHE_BLOCK_SIZE ==
          bd->read(bd, block2sector(bd, 1), buf, BLOCK_CACHE_BLOCK_SIZE));
  KEXPECT_STREQ("written end", &buf[BLOCK_CACHE_BLOCK_SIZE - 20]);
}

static void get_shares_buffers_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): get shares buffers");
  setup_disk(dev);
  memobj_t* obj = dev_get_block_memobj(dev);

  // Note: it's a little silly to use 2 pointers, since they should be equal
  // anyways.
  bc_entry_t *blockA, *blockB;
  KEXPECT_EQ(0, block_cache_get(obj, 3, &blockA));
  KEXPECT_EQ(0, block_cache_get(obj, 3, &blockB));

  // Write to the first buffer, then put() it.
  kstrcpy(blockA->block, "written to A");
  block_cache_put(blockA, BC_FLUSH_SYNC);

  // Make sure we can still read it out of the second buffer.
  KEXPECT_EQ(0, kstrcmp(blockB->block, "written to A"));
  block_cache_put(blockB, BC_FLUSH_SYNC);
}

static void cache_size_test(dev_t dev) {
  KTEST_BEGIN("block_cache_get(): cache size");
  setup_disk(dev);
  memobj_t* obj = dev_get_block_memobj(dev);
  const int old_size = block_cache_get_size();
  block_cache_set_size(3);

  bc_entry_t *block0a, *block0b, *block1, *block2, *block3;
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0a));
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0b));
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block1));
  KEXPECT_EQ(0, block_cache_get(obj, 2, &block2));
  KEXPECT_EQ(-ENOMEM, block_cache_get(obj, 3, &block3));
  KEXPECT_NE(0x0, (int)block0a);
  KEXPECT_NE(0x0, (int)block0b);
  KEXPECT_NE(0x0, (int)block1);
  KEXPECT_NE(0x0, (int)block2);

  // Put back one of the refs to the first block and make sure we still can't
  // get a new block.
  if (block0a != 0x0 || block0b != 0x0)
    block_cache_put(block0a, BC_FLUSH_SYNC);
  KEXPECT_EQ(-ENOMEM, block_cache_get(obj, 3, &block3));

  // Put back the other ref, then make sure we can get the third block.
  if (block0a != 0x0 || block0b != 0x0)
    block_cache_put(block0b, BC_FLUSH_SYNC);
  KEXPECT_EQ(0, block_cache_get(obj, 3, &block3));
  KEXPECT_NE(0x0, (int)block3);

  // Clean up.
  if (block1) block_cache_put(block1, BC_FLUSH_SYNC);
  if (block2) block_cache_put(block2, BC_FLUSH_SYNC);
  if (block3) block_cache_put(block3, BC_FLUSH_SYNC);

  block_cache_set_size(old_size);
}

// Test that multiple threads calling block_cache_get() on the same block
// get the same block.
static void* get_thread_test_thread(void* arg) {
  bc_entry_t* entry = 0x0;
  memobj_t* obj = (memobj_t*)arg;
  KASSERT(0 == block_cache_get(obj, 1, &entry));
  return entry;
}

// Test that threads calling block_cache_lookup() on the block get either the
// same block, or NULL.
static void* lookup_thread_test_thread(void* arg) {
  bc_entry_t* entry = 0x0;
  memobj_t* obj = (memobj_t*)arg;
  KASSERT(0 == block_cache_lookup(obj, 1, &entry));
  return entry;
}

static void get_thread_test(dev_t dev) {
  const int kThreads = 10;
  KTEST_BEGIN("block_cache_get(): thread-safety test");
  kthread_t threads[kThreads * 2];
  memobj_t* obj = dev_get_block_memobj(dev);

  for (int i = 0; i < kThreads; ++i) {
    KASSERT(kthread_create(&threads[i],
                           &get_thread_test_thread, obj));
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < kThreads; ++i) {
    KASSERT(kthread_create(&threads[kThreads + i],
                           &lookup_thread_test_thread, obj));
    scheduler_make_runnable(threads[kThreads + i]);
  }

  bc_entry_t* blocks[kThreads];
  for (int i = 0; i < kThreads * 2; ++i) {
    blocks[i] = kthread_join(threads[i]);
  }

  KEXPECT_NE(0x0, (int)blocks[0]);
  block_cache_put(blocks[0], BC_FLUSH_SYNC);
  for (int i = 1; i < kThreads; ++i) {
    KEXPECT_EQ((int)blocks[0], (int)blocks[i]);
    if (blocks[i]) block_cache_put(blocks[i], BC_FLUSH_SYNC);
  }

  for (int i = kThreads; i < kThreads * 2; ++i) {
    if (blocks[i] != 0x0) {
      KEXPECT_EQ((int)blocks[0], (int)blocks[i]);
      block_cache_put(blocks[i], BC_FLUSH_SYNC);
    }
  }

  KEXPECT_EQ(0, block_cache_get_pin_count(obj, 1));
}

// Test that if multiple threads are calling get() and put(), they don't see
// stale data.  The threads get() the block, increment it's data, then put() it
// again.
#define PUT_THREAD_TEST_ITERS 10
#define PUT_THREAD_TEST_THREADS 10
typedef struct {
  memobj_t* obj;
  int thread_id;
} put_thread_test_args_t;
static void* put_thread_test_thread(void* arg) {
  put_thread_test_args_t* args = (put_thread_test_args_t*)arg;
  for (int i = 0; i < PUT_THREAD_TEST_ITERS; ++i) {
    bc_entry_t* block = 0x0;
    const int result = block_cache_get(args->obj, 1, &block);
    if (result == 0) {
      uint8_t* value = (uint8_t*)block->block;
      (*value)++;
      block_cache_put(block, BC_FLUSH_SYNC);
    }
  }
  return 0x0;
}

static void put_thread_test(ramdisk_t* rd, dev_t dev) {
  // Disable read blocking to force race condition.
  ramdisk_set_blocking(rd, 0, 1);
  struct memobj* obj = dev_get_block_memobj(dev);

  KTEST_BEGIN("block_cache_put(): thread-safety test");
  KEXPECT_EQ(0, block_cache_get_pin_count(obj, 1));
  kthread_t threads[PUT_THREAD_TEST_THREADS];
  put_thread_test_args_t args[PUT_THREAD_TEST_THREADS];

  // Initialize block to 0.
  bc_entry_t* block = 0x0;
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  uint8_t* value = (uint8_t*)block->block;
  *value = 0;
  block_cache_put(block, BC_FLUSH_SYNC);

  for (int i = 0; i < PUT_THREAD_TEST_THREADS; ++i) {
    args[i].obj = obj;
    args[i].thread_id = i;
    KASSERT(kthread_create(&threads[i],
                           &put_thread_test_thread, &args[i]));
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < PUT_THREAD_TEST_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  // Make sure the correct value is in the block.
  KASSERT(PUT_THREAD_TEST_ITERS * PUT_THREAD_TEST_THREADS < 256);
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  value = (uint8_t*)block->block;
  KEXPECT_EQ(PUT_THREAD_TEST_ITERS * PUT_THREAD_TEST_THREADS, *value);
  block_cache_put(block, BC_FLUSH_SYNC);

  ramdisk_set_blocking(rd, 1, 1);
}

// TODO(aoates): test BC_FLUSH_NONE and BC_FLUSH_ASYNC.

// TODO(aoates): a good test:
//  get()
//  put(BC_FLUSH_ASYNC)
//  get()  // runs before the flush thread
//  put(BC_FLUSH_NONE)
//  wait_for_flush()
//  * verify that the second put() didn't cancel the first's flush *

void block_cache_test() {
  KTEST_SUITE_BEGIN("block_cache test");

  // Set up a ramdisk to use for testing.
  ramdisk_t* ramdisk = 0x0;
  block_dev_t ramdisk_bd;
  KASSERT(ramdisk_create(RAMDISK_SIZE, &ramdisk) == 0);
  ramdisk_set_blocking(ramdisk, 1, 1);
  ramdisk_dev(ramdisk, &ramdisk_bd);

  dev_t dev = mkdev(DEVICE_MAJOR_RAMDISK, DEVICE_ID_UNKNOWN);
  KASSERT(dev_register_block(&ramdisk_bd, &dev) == 0);

  // Run tests.
  basic_get_test(dev);
  basic_lookup_test(dev);
  basic_write_test(dev);
  write_at_end_test(dev);
  get_shares_buffers_test(dev);
  cache_size_test(dev);
  get_thread_test(dev);
  put_thread_test(ramdisk, dev);

  // Cleanup.
  block_cache_clear_unpinned();  // Make sure all entries for dev are flushed.
  block_cache_log_stats();
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);
}
