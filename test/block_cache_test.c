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
#include "common/hash.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "dev/timer.h"
#include "memory/block_cache.h"
#include "memory/memory.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/test_params.h"

// TODO(aoates): rewrite this test to use a custom memobj so we don't have to
// use a ramdisk.

#define RAMDISK_SIZE (PAGE_SIZE * 8)
#define RAMDISK_BLOCKS (RAMDISK_SIZE / BLOCK_CACHE_BLOCK_SIZE)

#define RAMDISK_SECTOR_SIZE 512

static int block2sector(block_dev_t* bd, int block) {
  return block * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
}

static void setup_disk(apos_dev_t dev) {
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
            bd->write(bd, sector_offset, data, BLOCK_CACHE_BLOCK_SIZE, 0));
  }
}

static void basic_get_test(apos_dev_t dev) {
  KTEST_BEGIN("block_cache_get(): basic test");
  setup_disk(dev);

  memobj_t* obj = dev_get_block_memobj(dev);
  const int start_obj_refcount = obj->refcount;
  for (int i = 0; i < RAMDISK_BLOCKS; ++i) {
    bc_entry_t* block = 0x0;
    KEXPECT_EQ(0, block_cache_get(obj, i, &block));
    KEXPECT_NE(NULL, block);
    KEXPECT_EQ(virt2phys((addr_t)block->block), block->block_phys);
    KEXPECT_GT(obj->refcount, start_obj_refcount);

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
  KEXPECT_EQ(block0a, block0b);
  KEXPECT_NE(block0a, block1);
  block_cache_put(block0a, BC_FLUSH_SYNC);
  block_cache_put(block0b, BC_FLUSH_SYNC);
  block_cache_put(block1, BC_FLUSH_SYNC);
}

static void basic_lookup_test(apos_dev_t dev) {
  KTEST_BEGIN("block_cache_lookup(): basic test");
  setup_disk(dev);

  memobj_t* obj = dev_get_block_memobj(dev);

  bc_entry_t* block = (bc_entry_t*)0xABCD;
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(0x0, (addr_t)block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(0x0, (addr_t)block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 1, &block));
  KEXPECT_EQ(0x0, (addr_t)block);

  // Now get() the block.
  bc_entry_t* get_block = (bc_entry_t*)0xABCD;
  KEXPECT_EQ(0, block_cache_get(obj, 0, &get_block));
  KEXPECT_NE(0x0, (addr_t)get_block);

  // ..and make sure we can get it via lookup now.
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(get_block, block);
  KEXPECT_EQ(0, block_cache_lookup(obj, 0, &block));
  KEXPECT_EQ(get_block, block);

  KEXPECT_EQ(3, block_cache_get_pin_count(obj, 0));

  // Test add_pin while we're at it.
  block_cache_add_pin(block);
  KEXPECT_EQ(4, block_cache_get_pin_count(obj, 0));
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_NONE));

  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_put(block, BC_FLUSH_SYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(obj, 0));
}

// TODO(aoates): test running out of space on the free block stack

static void basic_write_test(apos_dev_t dev) {
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
          bd->read(bd, block2sector(bd, 1), buf, RAMDISK_SECTOR_SIZE, 0));
  KEXPECT_EQ(0, kstrcmp(buf, "written block"));

  // Write to the raw disk.
  kstrcpy(buf, "WRITTEN BLOCK");
  KASSERT(BLOCK_CACHE_BLOCK_SIZE ==
          bd->write(bd, block2sector(bd, 1), buf, BLOCK_CACHE_BLOCK_SIZE, 0));

  // Verify that if we get() it again we see the new data.
  block_cache_clear_unpinned();
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block));
  KEXPECT_EQ(0, kstrcmp(block->block, "WRITTEN BLOCK"));
  block_cache_put(block, BC_FLUSH_SYNC);
}

static void write_at_end_test(apos_dev_t dev) {
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
          bd->read(bd, block2sector(bd, 1), buf, BLOCK_CACHE_BLOCK_SIZE, 0));
  KEXPECT_STREQ("written end", &buf[BLOCK_CACHE_BLOCK_SIZE - 20]);
}

static void get_shares_buffers_test(apos_dev_t dev) {
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

static void cache_size_test(apos_dev_t dev) {
  KTEST_BEGIN("block_cache_get(): cache size");
  setup_disk(dev);
  memobj_t* obj = dev_get_block_memobj(dev);

  const int starting_entries = block_cache_get_num_entries();
  const int old_size = block_cache_get_size();
  const int new_size = starting_entries + 3;
  klogf("Resizing block cache from %d to %d\n", starting_entries, new_size);
  block_cache_set_size(new_size);

  bc_entry_t *block0a = 0x0, *block0b = 0x0, *block1 = 0x0, *block2 = 0x0,
             *block3 = 0x0;
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0a));
  KEXPECT_EQ(0, block_cache_get(obj, 0, &block0b));
  KEXPECT_EQ(0, block_cache_get(obj, 1, &block1));
  KEXPECT_EQ(0, block_cache_get(obj, 2, &block2));
  KEXPECT_EQ(-ENOMEM, block_cache_get(obj, 3, &block3));
  KEXPECT_NE(NULL, block0a);
  KEXPECT_NE(NULL, block0b);
  KEXPECT_NE(NULL, block1);
  KEXPECT_NE(NULL, block2);

  // Put back one of the refs to the first block and make sure we still can't
  // get a new block.
  if (block0a != 0x0 || block0b != 0x0)
    block_cache_put(block0a, BC_FLUSH_SYNC);
  KEXPECT_EQ(-ENOMEM, block_cache_get(obj, 3, &block3));

  // Put back the other ref, then make sure we can get the third block.
  if (block0a != 0x0 || block0b != 0x0)
    block_cache_put(block0b, BC_FLUSH_SYNC);
  KEXPECT_EQ(0, block_cache_get(obj, 3, &block3));
  KEXPECT_NE(NULL, block3);

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

static void get_thread_test(apos_dev_t dev) {
  const int kThreads = 10;
  KTEST_BEGIN("block_cache_get(): thread-safety test");
  kthread_t threads[kThreads * 2];
  memobj_t* obj = dev_get_block_memobj(dev);

  for (int i = 0; i < kThreads; ++i) {
    KASSERT(kthread_create(&threads[i],
                           &get_thread_test_thread, obj) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < kThreads; ++i) {
    KASSERT(kthread_create(&threads[kThreads + i],
                           &lookup_thread_test_thread, obj) == 0);
    scheduler_make_runnable(threads[kThreads + i]);
  }

  bc_entry_t* blocks[kThreads * 2];
  for (int i = 0; i < kThreads * 2; ++i) {
    blocks[i] = kthread_join(threads[i]);
  }

  KEXPECT_NE(NULL, blocks[0]);
  block_cache_put(blocks[0], BC_FLUSH_SYNC);
  for (int i = 1; i < kThreads; ++i) {
    KEXPECT_EQ(blocks[0], blocks[i]);
    if (blocks[i]) block_cache_put(blocks[i], BC_FLUSH_SYNC);
  }

  for (int i = kThreads; i < kThreads * 2; ++i) {
    if (blocks[i] != 0x0) {
      KEXPECT_EQ(blocks[0], blocks[i]);
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

static void put_thread_test(ramdisk_t* rd, apos_dev_t dev) {
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
                           &put_thread_test_thread, &args[i]) == 0);
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

static void unflushed_lru_block_test(apos_dev_t dev) {
  memobj_t* obj = dev_get_block_memobj(dev);
  block_dev_t* bd = dev_get_block(dev);

  uint8_t buf[RAMDISK_SECTOR_SIZE];
  for (int i = 0; i < 10; ++i) {
    bc_entry_t* entry = NULL;
    KEXPECT_EQ(0, block_cache_get(obj, 0, &entry));
    KEXPECT_EQ(1, block_cache_get_pin_count(obj, 0));
    *((uint8_t*)entry->block) = i;
    KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_ASYNC));
    KEXPECT_EQ(0, block_cache_get(obj, 0, &entry));
    KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
    block_cache_clear_unpinned();  // Force a flush cycle.

    // Ensure the write actually flushed.
    KEXPECT_EQ(RAMDISK_SECTOR_SIZE,
               bd->read(bd, 0, buf, RAMDISK_SECTOR_SIZE, 0));
    KEXPECT_EQ(i, buf[0]);
  }
}

static void reentrant_memobj_ref_unref(memobj_t* obj) {
  // In normal code, having the ref/unref try to touch the same entry as is
  // being get/put would obviously deadlock (barring a more interesting API).
  // But, for example, ext2 must read the inode tables when it writes back an
  // inode, which it does when a vnode memobj backed by that inode is
  // freed/unref'd.
  //
  // Here, we don't actually know what the underlying block being referenced is,
  // so we can't do any interesting operations on any blocks :/
  block_cache_get_pin_count(obj, 0);
}

static int reentrant_memobj_write_page(memobj_t* obj, int page_offset,
                                       const void* buffer) {
  bc_entry_t* entry = NULL;
  KEXPECT_LE(page_offset, 3);
  switch (page_offset) {
    case 0:
      return 0;

    case 1:
      KEXPECT_EQ(0, block_cache_get(obj, 0, &entry));
      KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
      return 0;

    case 2:
      KEXPECT_EQ(0, block_cache_get(obj, 0, &entry));
      KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_SYNC));
      return 0;

    case 3:
      KEXPECT_EQ(0, block_cache_get(obj, 0, &entry));
      KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_ASYNC));
      return 0;

    default:
      return -EINVAL;
  }
}
static int reentrant_memobj_read_page(memobj_t* obj, int page_offset,
                                      void* buffer) {
  return reentrant_memobj_write_page(obj, page_offset, buffer);
}

static memobj_ops_t reentrant_memobj_ops = {
    reentrant_memobj_ref_unref,  //
    reentrant_memobj_ref_unref,  //
    NULL,                        // get_page
    NULL,                        // put_page
    reentrant_memobj_read_page,  //
    reentrant_memobj_write_page,
};

// Test with a backing memobj that calls back into the block cache on reads and
// writes.
static void reentrant_memobj_test(void) {
  KTEST_BEGIN("block cache reentrant memobj test");
  memobj_t fake_obj;
  memobj_base_init(&fake_obj);
  fake_obj.type = MEMOBJ_FAKE;
  fake_obj.id = 1;
  fake_obj.ops = &reentrant_memobj_ops;

  for (int i = 0; i < 4; ++i) {
    bc_entry_t* entry;
    KEXPECT_EQ(0, block_cache_get(&fake_obj, i, &entry));
    KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
    KEXPECT_EQ(0, block_cache_get(&fake_obj, i, &entry));
    KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_SYNC));
    KEXPECT_EQ(0, block_cache_get(&fake_obj, i, &entry));
    KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_ASYNC));
    block_cache_wakeup_flush_thread();
  }

  block_cache_clear_unpinned();
}

static void* multithread_test_worker(void* arg) {
  sched_enable_preemption_for_test();
  uint32_t rand = fnv_hash(get_time_ms());
  rand = fnv_hash_concat(rand, fnv_hash(kthread_current_thread()->id));
  memobj_t* obj = (memobj_t*)arg;
  const int kMaxEntries = 10;
  bc_entry_t* entries[kMaxEntries];
  int entry_end_idx = 0;
  for (int i = 0; i < kMaxEntries; ++i) {
    entries[i] = NULL;
  }

  const int kNumIters = 1000 * CONCURRENCY_TEST_ITERS_MULT;
  for (int round = 0; round < kNumIters; ++round) {
    int action = rand % 3;  // get, lookup, or put.
    rand = fnv_hash(rand);
    if (entry_end_idx == 0 || (action == 0 && entry_end_idx < kMaxEntries)) {
      int block = rand % RAMDISK_BLOCKS;
      rand = fnv_hash(rand);
      KEXPECT_EQ(0, block_cache_get(obj, block, &entries[entry_end_idx]));
      entry_end_idx++;
    } else if (action == 1 && entry_end_idx < kMaxEntries) {
      int block = rand % RAMDISK_BLOCKS;
      rand = fnv_hash(rand);
      KEXPECT_EQ(0, block_cache_lookup(obj, block, &entries[entry_end_idx]));
      if (entries[entry_end_idx] != NULL) {
        entry_end_idx++;
      }
    } else {
      int entry_to_put = rand % entry_end_idx;
      rand = fnv_hash(rand);
      int flush_mode_idx = rand % 3;
      rand = fnv_hash(rand);
      block_cache_flush_t flush_mode =
          (flush_mode_idx == 0) ? BC_FLUSH_NONE : (flush_mode_idx == 1)
                                                      ? BC_FLUSH_SYNC
                                                      : BC_FLUSH_ASYNC;
      KEXPECT_EQ(0, block_cache_put(entries[entry_to_put], flush_mode));
      KASSERT(entry_end_idx > 0);
      for (int i = entry_to_put; i < entry_end_idx - 1; ++i) {
        entries[i] = entries[i + 1];
      }
      entries[entry_end_idx - 1] = NULL;
      entry_end_idx--;
    }
    if (rand % 100 == 0) {
      block_cache_wakeup_flush_thread();
    }
  }

  for (int i = 0; i < entry_end_idx; ++i) {
    KEXPECT_EQ(0, block_cache_put(entries[i], BC_FLUSH_NONE));
  }

  return NULL;
}

static void multithread_test(ramdisk_t* rd, apos_dev_t dev) {
  KTEST_BEGIN("block cache: multithreaded stress test");
  ramdisk_set_blocking(rd, 0, 0);
  const int kNumThreads = 10 * CONCURRENCY_TEST_THREADS_MULT;

  kthread_t threads[kNumThreads];
  memobj_t* obj = dev_get_block_memobj(dev);
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(0, kthread_create(&threads[i], multithread_test_worker, obj));
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
  ramdisk_set_blocking(rd, 1, 1);
}

static void* multithread_pressure_test_worker(void* arg) {
  sched_enable_preemption_for_test();
  uint32_t rand = fnv_hash(get_time_ms());
  rand = fnv_hash_concat(rand, fnv_hash(kthread_current_thread()->id));
  memobj_t* obj = (memobj_t*)arg;

  const int kNumIters = 1000 * CONCURRENCY_TEST_ITERS_MULT;
  for (int round = 0; round < kNumIters; ++round) {
    bc_entry_t* entry = NULL;
    rand = fnv_hash(rand);
    int block = rand % 4;
    int result = block_cache_get(obj, block, &entry);
    if (result != 0 && result != -ENOMEM) {
      KEXPECT_EQ(0, result);
    }
    if (entry) {
      KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
    }
  }

  return NULL;
}

static void multithread_pressure_test(ramdisk_t* rd, apos_dev_t dev) {
  KTEST_BEGIN("block cache: multithreaded stress test with small cache size");
  block_cache_clear_unpinned();
  // We want the ramdisk blocking for this test.
  int orig_max_size = block_cache_get_size();
  block_cache_set_size(3);
  const int kNumThreads = 4; // Don't scale with the test multipliers.

  kthread_t threads[kNumThreads];
  memobj_t* obj = dev_get_block_memobj(dev);
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(
        0, kthread_create(&threads[i], multithread_pressure_test_worker, obj));
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
  block_cache_set_size(orig_max_size);
  block_cache_clear_unpinned();
}

typedef struct {
  memobj_t obj;
  kthread_queue_t obj_queue;
  bool block_reads;
  bool block_writes;
  kmutex_t mu;
  int block_iteration;
  int waiting_readers;
  int waiting_writers;
  int op_result;
  const char* data;
} blocking_memobj_t;

static void blocking_memobj_ref_unref(memobj_t* obj) {}

static int blocking_memobj_write_page(memobj_t* obj, int page_offset,
                                       const void* buffer) {
  blocking_memobj_t* blocking_obj = (blocking_memobj_t*)obj->data;

  KMUTEX_AUTO_LOCK(lock, &blocking_obj->mu);
  if (!blocking_obj->block_writes) return blocking_obj->op_result;

  const int orig_bli = blocking_obj->block_iteration;
  while (blocking_obj->block_iteration == orig_bli) {
    blocking_obj->waiting_writers++;
    scheduler_wake_all(&blocking_obj->obj_queue);
    int result = scheduler_wait_on_locked(&blocking_obj->obj_queue, 1000,
                                          &blocking_obj->mu);
    KEXPECT_NE(result, SWAIT_TIMEOUT);
    blocking_obj->waiting_writers--;
    if (result == SWAIT_INTERRUPTED) return -EINTR;
  }
  return blocking_obj->op_result;
}

static int blocking_memobj_read_page(memobj_t* obj, int page_offset,
                                     void* buffer) {
  blocking_memobj_t* blocking_obj = (blocking_memobj_t*)obj->data;

  KMUTEX_AUTO_LOCK(lock, &blocking_obj->mu);
  if (!blocking_obj->block_reads) return blocking_obj->op_result;

  const int orig_bli = blocking_obj->block_iteration;
  while (blocking_obj->block_iteration == orig_bli) {
    blocking_obj->waiting_readers++;
    scheduler_wake_all(&blocking_obj->obj_queue);
    int result = scheduler_wait_on_locked(&blocking_obj->obj_queue, 1000,
                                          &blocking_obj->mu);
    KEXPECT_NE(result, SWAIT_TIMEOUT);
    blocking_obj->waiting_readers--;
    if (result == SWAIT_INTERRUPTED) return -EINTR;
  }
  if (blocking_obj->data) {
    kstrcpy(buffer, blocking_obj->data);
  }
  return blocking_obj->op_result;
}

static int blocking_memobj_id = 0;
static memobj_ops_t blocking_memobj_ops = {
    blocking_memobj_ref_unref,  //
    blocking_memobj_ref_unref,  //
    NULL,                        // get_page
    NULL,                        // put_page
    blocking_memobj_read_page,  //
    blocking_memobj_write_page,
};

static void create_blocking_memobj(blocking_memobj_t* obj) {
  memobj_base_init(&obj->obj);
  obj->obj.type = MEMOBJ_FAKE;
  obj->obj.id = blocking_memobj_id++;
  obj->obj.ops = &blocking_memobj_ops;
  obj->obj.data = obj;
  kthread_queue_init(&obj->obj_queue);
  kmutex_init(&obj->mu);
  obj->block_iteration = 0;
  obj->block_reads = true;
  obj->block_writes = true;
  obj->waiting_readers = 0;
  obj->waiting_writers = 0;
  obj->op_result = 0;
  obj->data = NULL;
}

static int bmo_get_readers(blocking_memobj_t* obj) {
  KMUTEX_AUTO_LOCK(mu, &obj->mu);
  return obj->waiting_readers;
}

static int bmo_get_writers(blocking_memobj_t* obj) {
  KMUTEX_AUTO_LOCK(mu, &obj->mu);
  return obj->waiting_writers;
}

static bool bmo_await_writers(blocking_memobj_t* obj, int writers) {
  KMUTEX_AUTO_LOCK(mu, &obj->mu);
  while (obj->waiting_writers < writers) {
    int result = scheduler_wait_on_locked(&obj->obj_queue, 1000, &obj->mu);
    if (result == SWAIT_TIMEOUT) return false;
  }
  return true;
}

static void bmo_wake_all(blocking_memobj_t* obj) {
  KMUTEX_AUTO_LOCK(mu, &obj->mu);
  obj->block_iteration++;
  scheduler_wake_all(&obj->obj_queue);
}

static void* do_block_cache_get_thread(void* arg) {
  memobj_t* obj = (memobj_t*)arg;
  bc_entry_t* entry = NULL;
  int result = block_cache_get(obj, 0, &entry);
  if (result == 0) {
    block_cache_put(entry, BC_FLUSH_NONE);
  }
  return (void*)(intptr_t)result;
}

static void do_block_cache_get_proc(void* arg) {
  proc_exit((intptr_t)do_block_cache_get_thread(arg));
}

static void do_block_cache_lookup_proc(void* arg) {
  memobj_t* obj = (memobj_t*)arg;
  bc_entry_t* entry = NULL;
  int result = block_cache_lookup(obj, 0, &entry);
  if (result == 0) {
    block_cache_put(entry, BC_FLUSH_NONE);
  }
  proc_exit(result);
}

static void do_block_cache_put_proc(void* arg) {
  memobj_t* obj = (memobj_t*)arg;
  bc_entry_t* entry = NULL;
  int result = block_cache_get(obj, 0, &entry);
  KEXPECT_EQ(0, result);
  result = block_cache_put(entry, BC_FLUSH_SYNC);
  if (result) {
    int result2 = block_cache_put(entry, BC_FLUSH_NONE);
    KEXPECT_EQ(0, result2);
  }
  proc_exit(result);
}

static void signal_interrupt_test(void) {
  // Test for when get() is waiting for another thread to initialize the entry
  // in question, and is interrupted during that wait.
  KTEST_BEGIN(
      "block_cache_{get,lookup}(): interrupted while waiting for entry "
      "initialization");

  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  // First child: start the initialization.
  kpid_t child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // Let 'er run and start.  Would be better to synchronize explicitly.
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  // Second child: block on the initialization started by the first.
  kpid_t child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);

  // Third child: block as well, but in lookup.
  kpid_t child3 = proc_fork(&do_block_cache_lookup_proc, &blocking_memobj.obj);
  KEXPECT_GE(child3, 0);
  ksleep(10);  // Get them blocking.
  // Shouldn't be blocking on the underlying device.
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  KEXPECT_EQ(0, proc_kill(child2, SIGINT));
  KEXPECT_EQ(0, proc_kill(child3, SIGINT));

  int status;
  KEXPECT_EQ(child2, proc_waitpid(child2, &status, 0));
  KEXPECT_EQ(-EINTR, status);
  KEXPECT_EQ(child3, proc_waitpid(child3, &status, 0));
  KEXPECT_EQ(-EINTR, status);

  bmo_wake_all(&blocking_memobj);
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(0, status);

  // TODO(aoates): this only tests when one thread is waiting on another that is
  // actually doing the flush.  Also test (and fix) interruptions when this
  // thread is the one flushing.
  KTEST_BEGIN(
      "block_cache_put(): interrupted while waiting on synchronous flush");
  blocking_memobj.block_reads = false;
  kpid_t child4 = proc_fork(&do_block_cache_put_proc, &blocking_memobj.obj);
  KEXPECT_GE(child4, 0);
  // Let 'er run and start.  Would be better to synchronize explicitly.
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_writers(&blocking_memobj));

  // Second child: block on the flush started by the first.
  kpid_t child5 = proc_fork(&do_block_cache_put_proc, &blocking_memobj.obj);
  KEXPECT_GE(child5, 0);
  ksleep(10);  // Get them blocking.
  KEXPECT_EQ(1, bmo_get_writers(&blocking_memobj));

  KEXPECT_EQ(0, proc_kill(child5, SIGINT));
  KEXPECT_EQ(child5, proc_waitpid(child5, &status, 0));
  KEXPECT_EQ(-EINTR, status);
  blocking_memobj.block_writes = false;
  bmo_wake_all(&blocking_memobj);
  KEXPECT_EQ(child4, proc_waitpid(child4, &status, 0));
  KEXPECT_EQ(0, status);

  block_cache_clear_unpinned();
}

static void read_error_test(void) {
  KTEST_BEGIN("block_cache_get(): read returns error (basic)");
  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  blocking_memobj.block_reads = false;
  blocking_memobj.op_result = -EXDEV;
  bc_entry_t* entry = NULL;
  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);
  KEXPECT_EQ(0, block_cache_lookup(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_get(): read returns error with 2nd thread waiting");
  // First child: start the initialization.
  create_blocking_memobj(&blocking_memobj);
  blocking_memobj.op_result = -EXDEV;

  kpid_t child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // TODO(aoates): use Notification here (and above and below).
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  kpid_t child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  // Have a third thread call via lookup().
  kpid_t child3 = proc_fork(&do_block_cache_lookup_proc, &blocking_memobj.obj);
  KEXPECT_GE(child3, 0);
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  bmo_wake_all(&blocking_memobj);
  int status;
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(-EXDEV, status);
  KEXPECT_EQ(child2, proc_waitpid(child2, &status, 0));
  KEXPECT_EQ(-EXDEV, status);
  KEXPECT_EQ(child3, proc_waitpid(child3, &status, 0));
  KEXPECT_EQ(-EXDEV, status);

  KEXPECT_EQ(0, block_cache_lookup(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_get(): read interrupted with 2nd thread waiting");
  // First child: start the initialization.
  create_blocking_memobj(&blocking_memobj);
  blocking_memobj.op_result = -EXDEV;

  child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // TODO(aoates): use Notification here (and above and below).
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);
  ksleep(10);
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  KEXPECT_EQ(0, proc_kill(child1, SIGUSR1));
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(-EINTR, status);
  KEXPECT_EQ(child2, proc_waitpid(child2, &status, 0));
  KEXPECT_EQ(-EINTR, status);

  KEXPECT_EQ(0, block_cache_lookup(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_get(): new thread gets while error pending");
  // First child: start the initialization.
  create_blocking_memobj(&blocking_memobj);
  blocking_memobj.op_result = -EXDEV;

  child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // TODO(aoates): use Notification here (and above and below).
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  kthread_t child2_thread;
  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  kthread_disable(child2_thread);

  bmo_wake_all(&blocking_memobj);
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(-EXDEV, status);

  // The second thread should have been woken, but not run yet.  Even though the
  // block cache entry is still live (in the second thread), it should not be
  // gettable --- we should start a fresh read (which we will let succeed).
  KEXPECT_EQ(0, block_cache_lookup(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);
  blocking_memobj.block_reads = false;
  blocking_memobj.op_result = 0;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry));
  KEXPECT_NE(NULL, entry);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));

  kthread_enable(child2_thread);
  KEXPECT_EQ(-EXDEV, (intptr_t)kthread_join(child2_thread));
  block_cache_clear_unpinned();


  KTEST_BEGIN(
      "block_cache_get(): read returns error, 2nd waiting thread interrupted");
  // Make sure that the second thread cleans things up even if it's interrupted.
  create_blocking_memobj(&blocking_memobj);
  blocking_memobj.op_result = -EXDEV;

  child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // TODO(aoates): use Notification here (and above and below).
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  kthread_disable(child2_thread);

  // Unlike above, interrupt the 2nd thread before letting the read fail.
  proc_kill_thread(child2_thread, SIGUSR1);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  bmo_wake_all(&blocking_memobj);
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(-EXDEV, status);

  KEXPECT_EQ(0, block_cache_lookup(&blocking_memobj.obj, 0, &entry));
  KEXPECT_EQ(NULL, entry);

  kthread_enable(child2_thread);
  KEXPECT_EQ(-EINTR, (intptr_t)kthread_join(child2_thread));
  block_cache_clear_unpinned();


  KTEST_BEGIN(
      "block_cache_get(): blocking read interrupted, cleans up entry");
  create_blocking_memobj(&blocking_memobj);
  blocking_memobj.op_result = 0;

  child1 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child1, 0);
  // TODO(aoates): use Notification here (and above and below).
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, bmo_get_readers(&blocking_memobj));

  kthread_disable(child2_thread);
  proc_kill_thread(child2_thread, SIGUSR1);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  bmo_wake_all(&blocking_memobj);
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(0, status);

  kthread_enable(child2_thread);
  KEXPECT_EQ(-EINTR, (intptr_t)kthread_join(child2_thread));

  block_cache_clear_unpinned();
}

static void write_error_test(void) {
  KTEST_BEGIN("block_cache_put(): write returns error (basic)");
  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  blocking_memobj.block_reads = false;
  blocking_memobj.block_writes = false;
  bc_entry_t* entry = NULL;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry));
  KEXPECT_NE(NULL, entry);

  blocking_memobj.op_result = -EXDEV;
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_SYNC));

  block_cache_clear_unpinned();
}

typedef struct {
  blocking_memobj_t* obj;
  notification_t done;
  int result;
} do_free_all_thread_args_t;

static void* do_free_all_thread(void* arg) {
  do_free_all_thread_args_t* args = (do_free_all_thread_args_t*)arg;
  args->result = block_cache_free_all(&args->obj->obj);
  ntfn_notify(&args->done);
  return NULL;
}

static void* do_get_second_block(void* arg) {
  do_free_all_thread_args_t* args = (do_free_all_thread_args_t*)arg;
  bc_entry_t* entry;
  args->result = block_cache_get(&args->obj->obj, 1, &entry);
  if (args->result == 0) {
    block_cache_put(entry, BC_FLUSH_NONE);
  }
  ntfn_notify(&args->done);
  return NULL;
}

static void free_all_memobj_testA(void) {
  KTEST_BEGIN("block_cache_free_all(): basic test");
  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  blocking_memobj.block_reads = false;
  blocking_memobj.block_writes = false;
  bc_entry_t* entry1 = NULL, *entry2 = NULL;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 1, &entry2));
  KEXPECT_NE(NULL, entry2);
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 1, &entry2));

  KEXPECT_EQ(2, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(1, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(2, block_cache_get_pin_count(&blocking_memobj.obj, 1));
  KEXPECT_EQ(-EBUSY, block_cache_free_all(&blocking_memobj.obj));

  KEXPECT_EQ(2, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(1, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(2, block_cache_get_pin_count(&blocking_memobj.obj, 1));

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(2, block_cache_get_pin_count(&blocking_memobj.obj, 1));
  KEXPECT_EQ(-EBUSY, block_cache_free_all(&blocking_memobj.obj));

  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 1));
  KEXPECT_EQ(0, block_cache_free_all(&blocking_memobj.obj));
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));


  KTEST_BEGIN("block_cache_free_all(): flushes dirty");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  do_free_all_thread_args_t args;
  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 100));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  bmo_wake_all(&blocking_memobj);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));


  KTEST_BEGIN("block_cache_free_all(): flushes dirty (then fails)");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 1, &entry2));
  KEXPECT_NE(NULL, entry2);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(1, block_cache_get_pin_count(&blocking_memobj.obj, 1));

  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 100));
  KEXPECT_EQ(2, list_size(&blocking_memobj.obj.bc_entries));
  bmo_wake_all(&blocking_memobj);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(-EBUSY, args.result);
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));

  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_free_all(&blocking_memobj.obj));


  KTEST_BEGIN("block_cache_free_all(): flush already happening");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(1, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));

  ntfn_init(&args.done);

  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));

  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  bmo_wake_all(&blocking_memobj);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));


  // As above, but also re-dirty the page while the flush is blocked.
  KTEST_BEGIN("block_cache_free_all(): flush already happening #2");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(1, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));

  ntfn_init(&args.done);

  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));
  kthread_disable(thread);

  // Allow the flush to finish and wake up the block_cache_free_all() thread
  // (which is waiting for it, but can't run because it's disabled).
  bmo_wake_all(&blocking_memobj);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Re-dirty the page.
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));

  // Wait for the flush queue thread to try _again_.
  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  // The waiting thread should see the entry flushing again, and wait again.
  // N.B.: an earlier implementation caught this scenario and gave up, returing
  // -EBUSY, rather than retrying.  That would also be valid behavior.
  kthread_enable(thread);
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  // Let the second flush finish.
  bmo_wake_all(&blocking_memobj);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(0, block_cache_free_all(&blocking_memobj.obj));


  KTEST_BEGIN(
      "block_cache_free_all(): flushes, but page is re-dirtied _after_ "
      "flushing");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  kthread_disable(thread);
  bmo_wake_all(&blocking_memobj);
  // Wait for the freeing thread to wake up, but not run yet.
  // TODO(aoates): invent a better way to do this.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Get and put the entry again, dirtying it.
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  blocking_memobj.block_writes = false;
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));

  // The freeing thread, which was doing the flushing, will see that the thread
  // is unflushed and retry (in flush_cache_entry()), allowing the free
  // operation to succeed.  This test is britle and relies on specific internals
  // of the block cache code, but I'm leaving it in for now to exercise the code
  // path.  The next test is a better test of this scenario.
  kthread_enable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));
  // Defense-in-depth check (since the flush thread should still see this entry)
  block_cache_wakeup_flush_thread();


  // As above, but have the flush queue thread doing the actual flushing.  This
  // is a better test, TBH.
  KTEST_BEGIN(
      "block_cache_free_all(): flushes, but page is re-dirtied _after_ "
      "flushing #2");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  // Wait for the flush queue thread to get blocked in the flush.
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  // The do_free_all_thread should now be blocked waiting for the flush thread.
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  kthread_disable(thread);
  bmo_wake_all(&blocking_memobj);
  // Wait for the freeing thread to wake up, but not run yet.
  // TODO(aoates): invent a better way to do this.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Get and put the entry again, dirtying it.
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  blocking_memobj.block_writes = false;
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));

  kthread_enable(thread);
  // The freeing thread should wake up, see that the block was dirtied again,
  // and retry the flush.  As N.B. above, it would also be valid for the thread
  // to give up and return -EBUSY.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));
  // Defense-in-depth check (since the flush thread should still see this entry)
  block_cache_wakeup_flush_thread();
  for (int i = 0; i < 10; ++i) scheduler_yield();

  block_cache_clear_unpinned();
}

static void free_all_memobj_testB(void) {
  KTEST_BEGIN(
      "block_cache_free_all(): flushes, but page is re-pinned during "
      "flushing");
  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  blocking_memobj.block_reads = false;
  blocking_memobj.block_writes = false;
  bc_entry_t* entry1 = NULL, *entry2 = NULL;

  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  do_free_all_thread_args_t args;
  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  kthread_disable(thread);
  bmo_wake_all(&blocking_memobj);
  // Wait for the freeing thread to wake up, but not run yet.
  // TODO(aoates): invent a better way to do this.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Get and pin the entry.
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));

  kthread_enable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(-EBUSY, args.result);
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));


  KTEST_BEGIN(
      "block_cache_free_all(): flushes, but page is freed while waiting");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);
  // Second entry, just for kicks.
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 1, &entry2));
  KEXPECT_NE(NULL, entry2);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  // Wait for the flush queue thread to get blocked in the flush.
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  // The do_free_all_thread should now be blocked waiting for the flush thread.
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));
  KEXPECT_EQ(2, list_size(&blocking_memobj.obj.bc_entries));
  kthread_disable(thread);
  bmo_wake_all(&blocking_memobj);
  // Wait for the freeing thread to wake up, but not run yet.
  // TODO(aoates): invent a better way to do this.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Force-free the entry (unless the block-cache code keeps it alive
  // correctly).
  block_cache_clear_unpinned();

  kthread_enable(thread);
  // The freeing thread should wake up but be able to deal with the fact that
  // the entry was freed (or alternatively, have kept it alive somehow despite
  // the block_cache_clear_unpinned() call above).
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));
  // Defense-in-depth check (since the flush thread should still see this entry)
  block_cache_wakeup_flush_thread();
  for (int i = 0; i < 10; ++i) scheduler_yield();


  // This is a very white-boxy and brittle test for the interaction between
  // cache flushing under memory pressure and block_cache_free_all().
  // N.B.: there is a small chance this test can flake if the flush thread wakes
  // up at just the wrong time (and flushes the dirty entry just before the get2
  // thread tries to free cache space).
  KTEST_BEGIN(
      "block_cache_free_all(): called while page is being flushed during cache "
      "resize");
  block_cache_clear_unpinned();
  blocking_memobj.block_writes = true;
  const int starting_entries = block_cache_get_num_entries();
  const int orig_max_size = block_cache_get_size();
  const int new_size = starting_entries + 1;
  block_cache_set_size(new_size);
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  // The block is now unpinned and on the LRU queue.  Start a get() in another
  // thread that will cause cache pressure and force a (blocking) flush/free of
  // the block.
  do_free_all_thread_args_t get2_args;
  get2_args.obj = &blocking_memobj;
  ntfn_init(&get2_args.done);
  kthread_t get2_thread;
  KEXPECT_EQ(
      0, proc_thread_create(&get2_thread, &do_get_second_block, &get2_args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&get2_args.done, 10));
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));
  kthread_disable(get2_thread);

  // Now run a free operation in another thread, which should block waiting on
  // the existing flush.
  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));

  // Let the flush finish.
  kthread_disable(thread);
  bmo_wake_all(&blocking_memobj);
  kthread_enable(get2_thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&get2_args.done, 2000));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(NULL, kthread_join(get2_thread));

  // Let the free thread finish.
  kthread_enable(thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);  // -EBUSY would also be acceptable.
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));
  block_cache_set_size(orig_max_size);


  // TODO(aoates): fix this behavior --- we currently silently eat the -EINTR
  // error, it should be passed back up.
  KTEST_BEGIN("block_cache_free_all(): interrupted while flushing");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));

  KEXPECT_EQ(0, proc_kill_thread(thread, SIGUSR1));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(0, args.result);  // Wrong!  Should be -EINTR!
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));


  // As above, but when we're waiting for another thread to flush.
  KTEST_BEGIN("block_cache_free_all(): interrupted while waiting for flush");
  blocking_memobj.block_writes = true;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_NE(NULL, entry1);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));

  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&blocking_memobj, 1));

  args.obj = &blocking_memobj;
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_free_all_thread, &args));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 10));

  KEXPECT_EQ(0, proc_kill_thread(thread, SIGUSR1));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 2000));
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(-EINTR, args.result);
  KEXPECT_EQ(1, list_size(&blocking_memobj.obj.bc_entries));

  // Let the flush queue finish.
  bmo_wake_all(&blocking_memobj);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  block_cache_clear_unpinned();
}

static void free_all_memobj_testC(void) {
  KTEST_BEGIN("block_cache_free_all(): free after error");
  // This tests the find-block-on-cleanup-list flow --- that can happen in cases
  // other than the error case, but this is the easiest way to trigger it for a
  // test.
  blocking_memobj_t blocking_memobj;
  create_blocking_memobj(&blocking_memobj);

  blocking_memobj.block_reads = false;
  blocking_memobj.op_result = -EXDEV;
  bc_entry_t* entry1 = NULL, *entry2 = NULL;
  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_EQ(NULL, entry1);

  KEXPECT_EQ(0, block_cache_free_all(&blocking_memobj.obj));
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));

  KTEST_BEGIN(
      "block_cache_free_all(): free after error (multiple extant entries)");
  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 0, &entry1));
  KEXPECT_EQ(NULL, entry1);
  blocking_memobj.op_result = 0;
  KEXPECT_EQ(0, block_cache_get(&blocking_memobj.obj, 1, &entry1));
  KEXPECT_NE(NULL, entry1);

  blocking_memobj.op_result = -EXDEV;
  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 2, &entry2));
  KEXPECT_EQ(NULL, entry2);

  // Do a little dance with freeing and getting again, just to add some entropy
  // to the test.
  KEXPECT_EQ(3, list_size(&blocking_memobj.obj.bc_entries));
  KEXPECT_EQ(-EBUSY, block_cache_free_all(&blocking_memobj.obj));

  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 0, &entry2));
  KEXPECT_EQ(NULL, entry2);
  KEXPECT_EQ(-EXDEV, block_cache_get(&blocking_memobj.obj, 2, &entry2));
  KEXPECT_EQ(NULL, entry2);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  KEXPECT_EQ(3, list_size(&blocking_memobj.obj.bc_entries));

  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 0));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 1));
  KEXPECT_EQ(0, block_cache_get_pin_count(&blocking_memobj.obj, 2));

  KEXPECT_EQ(0, block_cache_free_all(&blocking_memobj.obj));
  KEXPECT_EQ(0, list_size(&blocking_memobj.obj.bc_entries));

  block_cache_clear_unpinned();
}

static void block_cache_migrate_testA(void) {
  KTEST_BEGIN("block_cache_migrate(): basic migration");
  blocking_memobj_t obj1, obj2;
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;

  const int kBlockOffset = 5;
  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  void* e1_block = entry1->block;
  phys_addr_t e1_block_phys = entry1->block_phys;

  bc_entry_t* entry2 = NULL;
  KEXPECT_EQ(0, block_cache_migrate(entry1, &obj2.obj, &entry2));
  KEXPECT_NE(NULL, entry2);
  KEXPECT_NE(entry1, entry2);
  KEXPECT_EQ(&obj2.obj, entry2->obj);
  KEXPECT_EQ(e1_block, entry2->block);
  KEXPECT_EQ(e1_block_phys, entry2->block_phys);
  KEXPECT_EQ(kBlockOffset, entry2->offset);
  KEXPECT_EQ(NULL, entry1->block);
  KEXPECT_EQ(0, entry1->block_phys);

  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_migrate(): basic migration (drops page)");
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = obj2.block_reads = false;

  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  KEXPECT_EQ(0, block_cache_get(&obj2.obj, kBlockOffset, &entry2));
  kstrcpy(entry2->block, "ABCD");
  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  // Note: possible race if entry2 gets reaped now by another thread.  But we
  // don't want the entry pinned, so do the unsafe thing for this test.

  void* e2_block = entry2->block;
  phys_addr_t e2_block_phys = entry2->block_phys;

  bc_entry_t* entry3 = NULL;
  KEXPECT_EQ(0, block_cache_migrate(entry1, &obj2.obj, &entry3));
  // Should not have replaced the existing entry in the target.
  KEXPECT_EQ(entry3, entry2);
  KEXPECT_EQ(&obj2.obj, entry3->obj);
  KEXPECT_EQ(e2_block, entry3->block);
  KEXPECT_EQ(e2_block_phys, entry3->block_phys);
  KEXPECT_STREQ("ABCD", entry3->block);
  KEXPECT_EQ(kBlockOffset, entry3->offset);
  KEXPECT_EQ(NULL, entry1->block);
  KEXPECT_EQ(0, entry1->block_phys);
  // Ideally would confirm the page was freed, but not sure how to do that.

  KEXPECT_EQ(0, block_cache_put(entry3, BC_FLUSH_NONE));
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_migrate(): migration fails (entry in use)");
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = obj2.block_reads = false;

  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  block_cache_add_pin(entry1);
  KEXPECT_EQ(0, block_cache_get(&obj2.obj, kBlockOffset, &entry2));
  kstrcpy(entry2->block, "ABCD");

  e2_block = entry2->block;
  e2_block_phys = entry2->block_phys;

  entry3 = NULL;
  KEXPECT_EQ(-EBUSY, block_cache_migrate(entry1, &obj2.obj, &entry3));
  KEXPECT_EQ(NULL, entry3);
  KEXPECT_EQ(2, block_cache_get_pin_count(&obj1.obj, kBlockOffset));
  KEXPECT_STREQ("abcd", entry1->block);  // Should still be intact.
  KEXPECT_EQ(kBlockOffset, entry1->offset);
  // Should not have replaced the existing entry in the target.
  KEXPECT_EQ(e2_block, entry2->block);
  KEXPECT_EQ(e2_block_phys, entry2->block_phys);
  KEXPECT_STREQ("ABCD", entry2->block);
  KEXPECT_EQ(kBlockOffset, entry2->offset);
  KEXPECT_EQ(0, block_cache_get(&obj2.obj, kBlockOffset, &entry3));
  KEXPECT_EQ(entry2, entry3);

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(entry3, BC_FLUSH_NONE));
  block_cache_clear_unpinned();
}

typedef struct {
  bc_entry_t* entry;
  bc_entry_t* entry_out;
  blocking_memobj_t* target;
  int result;
  notification_t started, done;
  int offset;
} migrate_test_args_t;

static void* do_migrate_thread(void* arg) {
  migrate_test_args_t* args = (migrate_test_args_t*)arg;
  ntfn_notify(&args->started);
  args->result =
      block_cache_migrate(args->entry, &args->target->obj, &args->entry_out);
  ntfn_notify(&args->done);
  return NULL;
}

static void* do_get_thread(void* arg) {
  migrate_test_args_t* args = (migrate_test_args_t*)arg;
  ntfn_notify(&args->started);
  args->result =
      block_cache_get(&args->target->obj, args->offset, &args->entry_out);
  ntfn_notify(&args->done);
  return NULL;
}

static void block_cache_migrate_testB(void) {
  KTEST_BEGIN("block_cache_migrate(): migrate flushing entry");
  blocking_memobj_t obj1, obj2;
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;

  const int kBlockOffset = 5;
  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  void* entry1_block_orig = entry1->block;

  // Start flushing block in background thread.
  block_cache_add_pin(entry1);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, bmo_get_writers(&obj1));
  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&obj1, 1));

  // Start migration in background thread.
  migrate_test_args_t test_args;
  test_args.entry = entry1;
  test_args.target = &obj2;
  test_args.result = 0;
  ntfn_init(&test_args.started);
  ntfn_init(&test_args.done);
  kthread_t thread1;
  KEXPECT_EQ(0, proc_thread_create(&thread1, do_migrate_thread, &test_args));

  // Wait and make sure migration doesn't complete.
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&test_args.done, 50));

  // Let the flush and migration complete.
  KEXPECT_EQ(1, bmo_get_writers(&obj1));
  bmo_wake_all(&obj1);
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.done, 5000));
  KEXPECT_EQ(NULL, kthread_join(thread1));

  // Verify migration results.
  KEXPECT_EQ(0, test_args.result);
  KEXPECT_NE(NULL, test_args.entry_out);
  KEXPECT_STREQ("abcd", test_args.entry_out->block);
  KEXPECT_EQ(entry1_block_orig, test_args.entry_out->block);

  KEXPECT_EQ(0, block_cache_put(test_args.entry_out, BC_FLUSH_NONE));
  block_cache_clear_unpinned();


  KTEST_BEGIN("block_cache_migrate(): interrupted while waiting for flush");
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;

  entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  entry1_block_orig = entry1->block;

  // Start flushing block in background thread.
  block_cache_add_pin(entry1);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, bmo_get_writers(&obj1));
  block_cache_wakeup_flush_thread();
  KEXPECT_TRUE(bmo_await_writers(&obj1, 1));

  // Start migration in background thread.
  test_args.entry = entry1;
  test_args.target = &obj2;
  test_args.result = 0;
  test_args.entry_out = NULL;
  ntfn_init(&test_args.started);
  ntfn_init(&test_args.done);
  KEXPECT_EQ(0, proc_thread_create(&thread1, do_migrate_thread, &test_args));

  // Wait and make sure migration doesn't complete.
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&test_args.done, 10));

  // Signal the thread, then the migration should complete (with an error).
  KEXPECT_EQ(0, proc_kill_thread(thread1, SIGINT));
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.done, 5000));
  KEXPECT_EQ(NULL, kthread_join(thread1));
  KEXPECT_EQ(-EINTR, test_args.result);
  KEXPECT_EQ(NULL, test_args.entry_out);
  KEXPECT_STREQ("abcd", entry1->block);
  KEXPECT_EQ(entry1_block_orig, entry1->block);

  // ...finish by letting the flush complete and cleaning up.
  bmo_wake_all(&obj1);
  ksleep(20);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  block_cache_clear_unpinned();
}

static void block_cache_migrate_testC(void) {
  KTEST_BEGIN("block_cache_migrate(): target entry is initializing");
  blocking_memobj_t obj1, obj2;
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;
  obj2.data = "obj2_data";

  const int kBlockOffset = 5;
  migrate_test_args_t args;
  args.entry = args.entry_out = NULL;
  args.target = &obj2;
  ntfn_init(&args.started);
  ntfn_init(&args.done);
  args.offset = kBlockOffset;
  kthread_t get_thread;
  KEXPECT_EQ(0, proc_thread_create(&get_thread, &do_get_thread, &args));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));

  // Create entry in obj1, then start migration in another bg thread.
  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  void* entry1_block_orig = entry1->block;
  migrate_test_args_t args2;

  args2.entry = entry1;
  args2.entry_out = NULL;
  args2.target = &obj2;
  ntfn_init(&args2.started);
  ntfn_init(&args2.done);
  kthread_t migrate_thread;
  KEXPECT_EQ(0,
             proc_thread_create(&migrate_thread, &do_migrate_thread, &args2));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2.started, 5000));
  // The migration shouldn't complete since the target entry exists and is
  // initializing.
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2.done, 20));

  // Let initialization finish and verify the results.
  bmo_wake_all(&obj2);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 5000));
  KEXPECT_EQ(0, args.result);
  KEXPECT_STREQ("obj2_data", args.entry_out->block);
  KEXPECT_EQ(&obj2.obj, args.entry_out->obj);

  // The migration should complete as well, consuming the obj1 entry.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2.done, 5000));
  KEXPECT_EQ(0, args2.result);
  KEXPECT_EQ(args.entry_out, args2.entry_out);
  KEXPECT_STREQ("obj2_data", args2.entry_out->block);
  KEXPECT_EQ(&obj2.obj, args2.entry_out->obj);
  KEXPECT_NE(entry1_block_orig, args2.entry_out->block);

  KEXPECT_EQ(NULL, kthread_join(get_thread));
  KEXPECT_EQ(NULL, kthread_join(migrate_thread));

  KEXPECT_EQ(0, block_cache_lookup(&obj1.obj, kBlockOffset, &entry1));
  KEXPECT_EQ(NULL, entry1);  // Should not exist in obj1 anymore.

  KEXPECT_EQ(0, block_cache_put(args.entry_out, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(args2.entry_out, BC_FLUSH_NONE));
  block_cache_clear_unpinned();


  // As above, but initialization is blocking and fails.
  KTEST_BEGIN("block_cache_migrate(): target entry is initializing and fails");
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;
  obj2.op_result = -EXDEV;

  args.entry = args.entry_out = NULL;
  args.target = &obj2;
  ntfn_init(&args.started);
  ntfn_init(&args.done);
  args.offset = kBlockOffset;
  KEXPECT_EQ(0, proc_thread_create(&get_thread, &do_get_thread, &args));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));

  // Create entry in obj1, then start migration in another bg thread.
  entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  entry1_block_orig = entry1->block;

  args2.entry = entry1;
  args2.entry_out = NULL;
  args2.target = &obj2;
  ntfn_init(&args2.started);
  ntfn_init(&args2.done);
  KEXPECT_EQ(0,
             proc_thread_create(&migrate_thread, &do_migrate_thread, &args2));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2.started, 5000));
  // The migration shouldn't complete since the target entry exists and is
  // initializing.
  KEXPECT_FALSE(ntfn_await_with_timeout(&args2.done, 20));

  // Let initialization finish and verify the results.
  bmo_wake_all(&obj2);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 5000));
  KEXPECT_EQ(-EXDEV, args.result);
  KEXPECT_EQ(NULL, args.entry_out);

  // The migration should fail as well.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args2.done, 5000));
  KEXPECT_EQ(-EXDEV, args2.result);
  KEXPECT_EQ(NULL, args.entry_out);
  KEXPECT_EQ(entry1_block_orig, entry1->block);

  KEXPECT_EQ(NULL, kthread_join(get_thread));
  KEXPECT_EQ(NULL, kthread_join(migrate_thread));

  bc_entry_t* entry2 = NULL;
  KEXPECT_EQ(0, block_cache_lookup(&obj1.obj, kBlockOffset, &entry2));
  KEXPECT_EQ(entry1, entry2);  // Should STILL exist.

  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_NONE));
  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  block_cache_clear_unpinned();
}

static void block_cache_migrate_testD(void) {
  KTEST_BEGIN("block_cache_migrate(): migrate unflushed (not flushing) entry");
  blocking_memobj_t obj1, obj2;
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;

  const int kBlockOffset = 5;
  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  void* entry1_block_orig = entry1->block;

  // Request flush but don't wait for it to start.  Note that it's possible that
  // the flush thread will wake up and start flushing immediately depending on
  // test timing (reducing this case to the "migrate while flushing" scenario),
  // but generally shouldn't.
  block_cache_add_pin(entry1);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, bmo_get_writers(&obj1));

  // Start migration in background thread.
  migrate_test_args_t test_args;
  test_args.entry = entry1;
  test_args.target = &obj2;
  test_args.result = 0;
  ntfn_init(&test_args.started);
  ntfn_init(&test_args.done);
  kthread_t thread1;
  KEXPECT_EQ(0, proc_thread_create(&thread1, do_migrate_thread, &test_args));

  // Wait and make sure migration doesn't complete.
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&test_args.done, 50));

  // Let the flush and migration complete.
  KEXPECT_EQ(1, bmo_get_writers(&obj1));
  bmo_wake_all(&obj1);
  KEXPECT_TRUE(ntfn_await_with_timeout(&test_args.done, 5000));
  KEXPECT_EQ(NULL, kthread_join(thread1));

  // Verify migration results.
  KEXPECT_EQ(0, test_args.result);
  KEXPECT_NE(NULL, test_args.entry_out);
  KEXPECT_STREQ("abcd", test_args.entry_out->block);
  KEXPECT_EQ(entry1_block_orig, test_args.entry_out->block);

  KEXPECT_EQ(0, block_cache_put(test_args.entry_out, BC_FLUSH_NONE));
  block_cache_clear_unpinned();


  // As above, but the synchronous flush fails.
  KTEST_BEGIN("block_cache_migrate(): migrate unflushed entry, flush fails");
  create_blocking_memobj(&obj1);
  create_blocking_memobj(&obj2);
  obj1.block_reads = false;

  entry1 = NULL;
  KEXPECT_EQ(0, block_cache_get(&obj1.obj, kBlockOffset, &entry1));
  kstrcpy(entry1->block, "abcd");
  entry1_block_orig = entry1->block;

  // Request flush but don't wait for it to start.
  obj1.block_writes = false;
  obj1.op_result = -EXDEV;
  block_cache_add_pin(entry1);
  KEXPECT_EQ(0, block_cache_put(entry1, BC_FLUSH_ASYNC));
  KEXPECT_EQ(0, bmo_get_writers(&obj1));

  // Migration should succeed (error is logged but ignored).
  bc_entry_t* entry2 = NULL;
  KEXPECT_EQ(0, block_cache_migrate(entry1, &obj2.obj, &entry2));

  // Verify migration results.
  KEXPECT_NE(NULL, entry2);
  KEXPECT_STREQ("abcd", entry2->block);
  KEXPECT_EQ(entry1_block_orig, entry2->block);

  KEXPECT_EQ(0, block_cache_put(entry2, BC_FLUSH_NONE));
  block_cache_clear_unpinned();
}

// TODO(aoates): test BC_FLUSH_NONE and BC_FLUSH_ASYNC.

void block_cache_test(void) {
  KTEST_SUITE_BEGIN("block_cache test");

  // Set up a ramdisk to use for testing.
  ramdisk_t* ramdisk = 0x0;
  block_dev_t ramdisk_bd;
  KASSERT(ramdisk_create(RAMDISK_SIZE, &ramdisk) == 0);
  ramdisk_set_blocking(ramdisk, 1, 1);
  ramdisk_dev(ramdisk, &ramdisk_bd);

  apos_dev_t dev = kmakedev(DEVICE_MAJOR_RAMDISK, DEVICE_ID_UNKNOWN);
  KASSERT(dev_register_block(&ramdisk_bd, &dev) == 0);

  memobj_t* obj = dev_get_block_memobj(dev);
  const int start_obj_refcount = obj->refcount;

  // Run tests.
  int old_flush_period_ms = block_cache_set_bg_flush_period(100);
  basic_get_test(dev);
  basic_lookup_test(dev);
  basic_write_test(dev);
  write_at_end_test(dev);
  get_shares_buffers_test(dev);
  cache_size_test(dev);
  get_thread_test(dev);
  put_thread_test(ramdisk, dev);
  unflushed_lru_block_test(dev);
  reentrant_memobj_test();

  multithread_test(ramdisk, dev);
  multithread_pressure_test(ramdisk, dev);

  signal_interrupt_test();

  read_error_test();
  write_error_test();
  free_all_memobj_testA();
  free_all_memobj_testB();
  free_all_memobj_testC();

  block_cache_migrate_testA();
  block_cache_migrate_testB();
  block_cache_migrate_testC();
  block_cache_migrate_testD();

  // Cleanup.
  block_cache_set_bg_flush_period(old_flush_period_ms);
  block_cache_clear_unpinned();  // Make sure all entries for dev are flushed.
  KEXPECT_EQ(start_obj_refcount, obj->refcount);

  block_cache_log_stats();
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);
}
