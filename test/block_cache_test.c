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
#include "memory/block_cache.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "dev/timer.h"
#include "memory/memory.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
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

  bc_entry_t* blocks[kThreads];
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
  // TODO(aoates): use atomics for these.
  int waiting_readers;
  int waiting_writers;
  int op_result;
} blocking_memobj_t;

static void blocking_memobj_ref_unref(memobj_t* obj) {}

static int blocking_memobj_write_page(memobj_t* obj, int page_offset,
                                       const void* buffer) {
  blocking_memobj_t* blocking_obj = (blocking_memobj_t*)obj->data;
  if (!blocking_obj->block_writes) return blocking_obj->op_result;

  blocking_obj->waiting_writers++;
  int result = scheduler_wait_on_interruptable(&blocking_obj->obj_queue, 1000);
  KEXPECT_NE(result, SWAIT_TIMEOUT);
  blocking_obj->waiting_writers--;
  if (result == SWAIT_INTERRUPTED) return -EINTR;
  return blocking_obj->op_result;
}

static int blocking_memobj_read_page(memobj_t* obj, int page_offset,
                                     void* buffer) {
  blocking_memobj_t* blocking_obj = (blocking_memobj_t*)obj->data;
  if (!blocking_obj->block_reads) return blocking_obj->op_result;

  blocking_obj->waiting_readers++;
  int result = scheduler_wait_on_interruptable(&blocking_obj->obj_queue, 1000);
  KEXPECT_NE(result, SWAIT_TIMEOUT);
  blocking_obj->waiting_readers--;
  if (result == SWAIT_INTERRUPTED) return -EINTR;
  return blocking_obj->op_result;
}

static memobj_ops_t blocking_memobj_ops = {
    blocking_memobj_ref_unref,  //
    blocking_memobj_ref_unref,  //
    NULL,                        // get_page
    NULL,                        // put_page
    blocking_memobj_read_page,  //
    blocking_memobj_write_page,
};

static void create_blocking_memobj(blocking_memobj_t* obj) {
  obj->obj.type = MEMOBJ_FAKE;
  obj->obj.id = get_time_ms();
  obj->obj.ops = &blocking_memobj_ops;
  obj->obj.refcount = 1;
  obj->obj.lock = KSPINLOCK_NORMAL_INIT;
  obj->obj.data = obj;
  kthread_queue_init(&obj->obj_queue);
  obj->block_reads = true;
  obj->block_writes = true;
  obj->waiting_readers = 0;
  obj->waiting_writers = 0;
  obj->op_result = 0;
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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  // Second child: block on the initialization started by the first.
  kpid_t child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);

  // Third child: block as well, but in lookup.
  kpid_t child3 = proc_fork(&do_block_cache_lookup_proc, &blocking_memobj.obj);
  KEXPECT_GE(child3, 0);
  ksleep(10);  // Get them blocking.
  // Shouldn't be blocking on the underlying device.
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  KEXPECT_EQ(0, proc_kill(child2, SIGINT));
  KEXPECT_EQ(0, proc_kill(child3, SIGINT));

  int status;
  KEXPECT_EQ(child2, proc_waitpid(child2, &status, 0));
  KEXPECT_EQ(-EINTR, status);
  KEXPECT_EQ(child3, proc_waitpid(child3, &status, 0));
  KEXPECT_EQ(-EINTR, status);

  scheduler_wake_all(&blocking_memobj.obj_queue);
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
  KEXPECT_EQ(1, blocking_memobj.waiting_writers);

  // Second child: block on the flush started by the first.
  kpid_t child5 = proc_fork(&do_block_cache_put_proc, &blocking_memobj.obj);
  KEXPECT_GE(child5, 0);
  ksleep(10);  // Get them blocking.
  KEXPECT_EQ(1, blocking_memobj.waiting_writers);

  KEXPECT_EQ(0, proc_kill(child5, SIGINT));
  KEXPECT_EQ(child5, proc_waitpid(child5, &status, 0));
  KEXPECT_EQ(-EINTR, status);
  blocking_memobj.block_writes = false;
  scheduler_wake_all(&blocking_memobj.obj_queue);
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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  kpid_t child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);
  ksleep(10);
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  // Have a third thread call via lookup().
  kpid_t child3 = proc_fork(&do_block_cache_lookup_proc, &blocking_memobj.obj);
  KEXPECT_GE(child3, 0);
  ksleep(10);
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  scheduler_wake_all(&blocking_memobj.obj_queue);
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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  child2 = proc_fork(&do_block_cache_get_proc, &blocking_memobj.obj);
  KEXPECT_GE(child2, 0);
  ksleep(10);
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  kthread_t child2_thread;
  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  kthread_disable(child2_thread);

  scheduler_wake_all(&blocking_memobj.obj_queue);
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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  kthread_disable(child2_thread);

  // Unlike above, interrupt the 2nd thread before letting the read fail.
  proc_kill_thread(child2_thread, SIGUSR1);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  scheduler_wake_all(&blocking_memobj.obj_queue);
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
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  KEXPECT_EQ(0, proc_thread_create(&child2_thread, &do_block_cache_get_thread,
                                   &blocking_memobj.obj));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(1, blocking_memobj.waiting_readers);

  kthread_disable(child2_thread);
  proc_kill_thread(child2_thread, SIGUSR1);
  for (int i = 0; i < 10; ++i) scheduler_yield();

  scheduler_wake_all(&blocking_memobj.obj_queue);
  KEXPECT_EQ(child1, proc_waitpid(child1, &status, 0));
  KEXPECT_EQ(0, status);

  kthread_enable(child2_thread);
  KEXPECT_EQ(-EINTR, (intptr_t)kthread_join(child2_thread));

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

  block_cache_set_bg_flush_period(old_flush_period_ms);

  // Cleanup.
  block_cache_clear_unpinned();  // Make sure all entries for dev are flushed.
  KEXPECT_EQ(start_obj_refcount, obj->refcount);

  block_cache_log_stats();
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);
}
