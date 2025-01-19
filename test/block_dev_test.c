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

#include "common/kassert.h"
#include "common/errno.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "memory/kmalloc.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "test/ktest.h"

static void basic_test(block_dev_t* bd) {
  KTEST_BEGIN("block device test");
  KEXPECT_EQ(bd->sector_size, 512);

  KTEST_BEGIN("non-aligned parameters");
  char buf[1024];
  KEXPECT_EQ(-EINVAL, bd->read(bd, 0, buf, 768, 0));
  KEXPECT_EQ(-EINVAL, bd->write(bd, 0, buf, 768, 0));

  kmemset(buf, 1, 256);
  kmemset(buf + 256, 2, 256);
  kmemset(buf + 512, 3, 256);
  kmemset(buf + 768, 3, 256);

  KTEST_BEGIN("zero-length read()");
  KEXPECT_EQ(0, bd->read(bd, 0, buf, 0, 0));

  KTEST_BEGIN("zero-length write()");
  KEXPECT_EQ(0, bd->write(bd, 0, buf, 0, 0));

  char golden_buf[1024];
  kmemcpy(golden_buf, buf, 1024);

  KTEST_BEGIN("write() then read()");
  KEXPECT_EQ(1024, bd->write(bd, 5, buf, 1024, 0));
  kmemset(buf, 0, 1024);

  KEXPECT_EQ(1024, bd->read(bd, 5, buf, 1024, 0));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 1024));

  KTEST_BEGIN("small read()");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(512, bd->read(bd, 5, buf, 512, 0));
  KEXPECT_NE(0, kmemcmp(buf, golden_buf, 1024));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));

  KTEST_BEGIN("past-end-of-file read()");
  KEXPECT_EQ(0, bd->read(bd, bd->sectors + 1, buf, 1024, 0));

  KTEST_BEGIN("past-end-of-file write()");
  KEXPECT_EQ(0, bd->write(bd, bd->sectors + 1, buf, 1024, 0));

  KTEST_BEGIN("runs past-end-of-file write()");
  KEXPECT_EQ(512, bd->write(bd, bd->sectors - 1, golden_buf, 1024, 0));

  KTEST_BEGIN("runs past-end-of-file read()");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(512, bd->read(bd, bd->sectors - 1, buf, 1024, 0));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));

  KTEST_BEGIN("overlapping write()s");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->write(bd, 5, golden_buf, 1024, 0));
  KEXPECT_EQ(1024, bd->write(bd, 6, golden_buf, 1024, 0));

  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->read(bd, 5, buf, 1024, 0));
  // Should be the first and second 256-byte blocks repeated twice.
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));
  KEXPECT_EQ(0, kmemcmp(buf + 512, golden_buf, 512));

  KTEST_BEGIN("multi write() then read() test");
  kmemset(buf, 1, 1024);
  KEXPECT_EQ(512, bd->write(bd, 0, buf, 512, 0));
  kmemset(buf, 2, 1024);
  KEXPECT_EQ(512, bd->write(bd, 1, buf, 512, 0));

  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->read(bd, 0, buf, 1024, 0));

  char golden2[1024];
  kmemset(golden2, 1, 512);
  kmemset(golden2 + 512, 2, 512);
  KEXPECT_EQ(0, kmemcmp(buf, golden2, 1024));

  // Test reading/writing a really large (multi-page) block.
  KTEST_BEGIN("multi-page read/write");
  const int BIG_BUF_SIZE = 4096 * 3;
  char* big_buf = (char*)kmalloc(BIG_BUF_SIZE);
  KASSERT(BIG_BUF_SIZE % bd->sector_size == 0);
  for (int i = 0; i < BIG_BUF_SIZE / bd->sector_size; ++i) {
    kmemset(big_buf + i * bd->sector_size, i, bd->sector_size);
  }

  int result = bd->write(bd, 0, big_buf, BIG_BUF_SIZE, 0);
  // Make sure we wrote at least a page of it.
  KEXPECT_GE(result, 4096);

  // Read and verify.
  kmemset(big_buf, 0, BIG_BUF_SIZE);
  result = bd->read(bd, 0, big_buf, BIG_BUF_SIZE, 0);
  KEXPECT_GE(result, 4096);

  // Verify what we got back.
  KASSERT(result % bd->sector_size == 0);
  for (int i = 0; i < result / bd->sector_size; ++i) {
    kmemset(buf, i, bd->sector_size);
    KEXPECT_EQ(0, kmemcmp(buf, big_buf + i * bd->sector_size, bd->sector_size));
  }

  kfree(big_buf);
}

#define INTERRUPT_ITERATIONS 1000

static void do_op(void* arg) {
  block_dev_t* bd = (block_dev_t*)arg;
  void* buf = kmalloc(PAGE_SIZE);
  bool success = false;
  for (int i = 0; i < INTERRUPT_ITERATIONS; ++i) {
    int result = bd->read(bd, 0, buf, PAGE_SIZE, 0);
    if (result == -EINTR || result == -ETIMEDOUT) {
      success = true;
      break;
    }
  }
  if (!success) {
    klogfm(KL_TEST, WARNING,
           "block device interrupt test was unable to get EINTR or ETIMEDOUT "
           "after %d iterations\n",
           INTERRUPT_ITERATIONS);
  }
  kfree(buf);
}

// Tests for operations that are interrupted or time out.
static void interrupt_op_test(block_dev_t* bd) {
  KTEST_BEGIN("block device interrupted read test");
  kpid_t child = proc_fork(&do_op, bd);
  KEXPECT_GE(child, 0);
  ksleep(10);
  proc_kill(child, SIGKILL);
  KEXPECT_EQ(child, proc_wait(NULL));
}

void bd_standard_test(block_dev_t* bd) {
  basic_test(bd);
  interrupt_op_test(bd);
}

#define THREAD_TEST_VERBOSE 0

typedef struct {
  block_dev_t* bd;
  int dev_num;

  // The number of threads, per block device, to spawn.  Each thread will read
  // and write every NUM_THREADS blocks.
  uint32_t NUM_THREADS;

  // Number of blocks for each thread to read/write.  So the total number of
  // blocks accessed on each block device will be NUM_THREADS * NUM_BLOCKS.
  uint32_t NUM_BLOCKS;

  // Each thread will write to every block i * NUM_THREADS + offset, for i in
  // [0, NUM_BLOCKS).
  uint32_t offset;

  // A unique ID across all threads in the system.
  uint32_t id;
} bd_thread_test_t;

// TODO(aoates): it would be neat to test multi-sector writing as well.
void* bd_thread_test_func(void* arg) {
  bd_thread_test_t* t = (bd_thread_test_t*)arg;
  uint32_t* buf = (uint32_t*)kmalloc(t->bd->sector_size);

  if (THREAD_TEST_VERBOSE) {
    KLOG("thread %d started\n", t->id);
  }
  for (uint32_t i = 0; i < t->NUM_BLOCKS; i++) {
    const uint32_t block = i * t->NUM_THREADS + t->offset;
    // Write to the block.
    const uint32_t val = t->id + i;
    for (uint32_t j = 0; j < t->bd->sector_size / sizeof(uint32_t); ++j) {
      buf[j] = val;
    }

    // Write the block to the disk.
    if (THREAD_TEST_VERBOSE) {
      KLOG("thread %d writing block %u (actual block %u)\n", t->id, i, block);
    }
    int result = t->bd->write(t->bd, block, buf, t->bd->sector_size, 0);
    if (result != t->bd->sector_size) {
      KLOG("failed: block %d on dev %d in thread %d didn't match: "
           "write failed (expected %d, got %d)\n",
           block, t->dev_num, t->id, t->bd->sector_size, result);
      return (void*)1;
    }

    // Occasionally issue a read as well.
    kmemset(buf, 0xff, t->bd->sector_size);
    if (i % 3 == 0) {
      result = t->bd->read(t->bd, block, buf, t->bd->sector_size, 0);
      if (result != t->bd->sector_size) {
        KLOG(
            "failed: block %d on dev %d in thread %d didn't match: "
            "read failed (expected %d, got %d)\n",
            block, t->dev_num, t->id, t->bd->sector_size, result);
        return (void*)1;
      }

      for (uint32_t j = 0; j < t->bd->sector_size / sizeof(uint32_t); ++j) {
        if (buf[j] != val) {
          KTEST_ADD_FAILUREF(
              "thread %d block %d index %d was 0x%x, expected 0x%x\n", t->id,
              block, j, buf[j], val);
          break;
        }
      }
    }

    scheduler_yield();
  }

  // Go back and verify all the blocks we just wrote.
  for (uint32_t i = 0; i < t->NUM_BLOCKS; i++) {
    const uint32_t block = i * t->NUM_THREADS + t->offset;
    const uint32_t expected_val = t->id + i;

    // Read the block.
    if (THREAD_TEST_VERBOSE) {
      KLOG("thread %d reading block %u (actual block %u)\n", t->id, i, block);
    }
    int result = t->bd->read(t->bd, block, buf, t->bd->sector_size, 0);
    if (result != t->bd->sector_size) {
      KLOG("failed: block %d on dev %d in thread %d didn't match: "
           "read failed (expected %d, got %d)\n",
           block, t->dev_num, t->id, t->bd->sector_size, result);
      return (void*)1;
    }

    // Make sure it's the same thing we wrote.
    for (uint32_t j = 0; j < t->bd->sector_size / sizeof(uint32_t); ++j) {
      if (buf[j] != expected_val) {
        KLOG("failed: block %d, index %d on dev %d in thread %d didn't match: "
             "expected 0x%x, found 0x%x\n",
             block, j, t->dev_num, t->id, expected_val, buf[j]);
        return (void*)1;
      }
    }
    scheduler_yield();
  }
  if (THREAD_TEST_VERBOSE) {
    KLOG("thread %d done\n", t->id);
  }
  kfree(buf);
  return 0;
}

void bd_thread_test(block_dev_t** bds, int len,
                    uint32_t num_threads, uint32_t num_blocks) {
  KTEST_BEGIN("multi-thread block device test");
  // One thread and test struct for each thread and block dev.
  bd_thread_test_t* ts =
      (bd_thread_test_t*)kmalloc(len * num_threads * sizeof(bd_thread_test_t));
  kthread_t* threads =
      (kthread_t*)kmalloc(len * num_threads * sizeof(kthread_t));
  int idx = 0;

  // For each block device, create a thread.
  for (int bd_idx = 0; bd_idx < len; ++bd_idx) {
    for (uint32_t thread_idx = 0; thread_idx < num_threads; ++thread_idx) {
      ts[idx].bd = bds[bd_idx];
      ts[idx].dev_num = bd_idx;
      ts[idx].NUM_THREADS = num_threads;
      ts[idx].NUM_BLOCKS = num_blocks;
      ts[idx].offset = thread_idx;  // Offset is per-bd.
      ts[idx].id = idx;  // ID is global.
      KASSERT(kthread_create(&threads[idx],
                             &bd_thread_test_func, (void*)(&ts[idx])) == 0);
      idx++;
    }
  }
  for (int i = 0; i < idx; ++i) {
    scheduler_make_runnable(threads[i]);
  }

  // Make sure each thread succeeds.
  for (int i = 0; i < idx; ++i) {
    KEXPECT_EQ(NULL, kthread_join(threads[i]));
  }

  kfree(ts);
  kfree(threads);
}
