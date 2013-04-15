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
#include "memory/kmalloc.h"
#include "memory/mmap.h"
#include "memory/vm.h"
#include "proc/process.h"
#include "test/ktest.h"

// Test readability for a region under read/write and user/kernel.
static void EXPECT_REGION(addr_t start, addr_t end,
                          int kernel_read, int kernel_write,
                          int user_read, int user_write) {
  KEXPECT_EQ(kernel_read,
             vm_verify_region(proc_current(), start, end, 0, 0));
  KEXPECT_EQ(kernel_write,
             vm_verify_region(proc_current(), start, end, 1, 0));

  KEXPECT_EQ(user_read,
             vm_verify_region(proc_current(), start, end, 0, 1));
  KEXPECT_EQ(user_write,
             vm_verify_region(proc_current(), start, end, 1, 1));
}

static void vm_region_basic() {
  KTEST_BEGIN("vm_verify_region() kernel heap test");

  void* test_region = kmalloc(10);

  // Test reading and writing to the kernel heap.
  EXPECT_REGION((addr_t)test_region, (addr_t)test_region + 10,
                0, 0, -EFAULT, -EFAULT);

  kfree(test_region);

  KTEST_BEGIN("vm_verify_region() kernel code test");
  // TODO(aoates): test kernel accesses when we have regions for the initial
  // global mappings.
  KEXPECT_EQ(-EFAULT, vm_verify_region(proc_current(), (addr_t)&vm_region_basic,
                                       (addr_t)&vm_region_basic + 10,
                                       0, 1));
  KEXPECT_EQ(-EFAULT, vm_verify_region(proc_current(), (addr_t)&vm_region_basic,
                                       (addr_t)&vm_region_basic + 10,
                                       1, 1));
}

static void vm_region_mmap() {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d R/W region");

  void* addr = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addr));

  EXPECT_REGION((addr_t)addr, (addr_t)addr + kRegionSize,
                0, 0, 0, 0);

  KTEST_BEGIN("vm_verify_region() one byte of region");
  EXPECT_REGION((addr_t)addr, (addr_t)addr + 1,
                0, 0, 0, 0);

  KTEST_BEGIN("vm_verify_region() one past end of region");
  EXPECT_REGION((addr_t)addr, (addr_t)addr + kRegionSize + 1,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() middle of region");
  EXPECT_REGION((addr_t)addr + 20, (addr_t)addr + kRegionSize - 20,
                0, 0, 0, 0);

  // Test reading past the region we just allocated.
  KTEST_BEGIN("vm_verify_region() past end of region");
  EXPECT_REGION((addr_t)addr + kRegionSize, (addr_t)addr + 2 * kRegionSize,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() overlap start of region");
  EXPECT_REGION((addr_t)addr - 20, (addr_t)addr + kRegionSize - 20,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() overlap end of region");
  EXPECT_REGION((addr_t)addr + 20, (addr_t)addr + kRegionSize + 20,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() overlap start and end of region");
  EXPECT_REGION((addr_t)addr - 20, (addr_t)addr + kRegionSize + 20,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() after unmapping region");
  KEXPECT_EQ(0, do_munmap(addr, kRegionSize));
  EXPECT_REGION((addr_t)addr + kRegionSize, (addr_t)addr + 2 * kRegionSize,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() before all mapped regions");
  EXPECT_REGION(1, 2,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_region() after all mapped regions");
  EXPECT_REGION(0xFFFFFFFE, 0xFFFFFFFF,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);
}

static void vm_region_mmap_ro() {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d R/O region");

  void* addr = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_READ | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addr));

  EXPECT_REGION((addr_t)addr, (addr_t)addr + kRegionSize,
                0, -EFAULT, 0, -EFAULT);

  KEXPECT_EQ(0, do_munmap(addr, kRegionSize));
}

// Map two regions with a hole in the middle.
static void vm_region_mmap_hole() {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d regions with hole");

  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addrA));
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize + PAGE_SIZE, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                        -1, 0, &addrB));

  EXPECT_REGION((addr_t)addrA, (addr_t)addrA + kRegionSize,
                0, 0, 0, 0);

  EXPECT_REGION((addr_t)addrB, (addr_t)addrB + kRegionSize,
                0, 0, 0, 0);

  // Can't access region in the hole.
  EXPECT_REGION((addr_t)addrA + kRegionSize + 10,
                (addr_t)addrA + kRegionSize + 20,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  // Can't access region spanning the hole.
  EXPECT_REGION((addr_t)addrA, (addr_t)addrB + kRegionSize,
                -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  // Now map a R/O area into the hole.
  KTEST_BEGIN("vm_verify_region() mmap()'d regions with R/O middle region");
  void* addrC = 0x0;
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize, PAGE_SIZE,
                        PROT_READ | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                        -1, 0, &addrC));

  // Should be able to read across the whole region, but not write.
  EXPECT_REGION((addr_t)addrA, (addr_t)addrB + kRegionSize,
                0, -EFAULT, 0, -EFAULT);

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrB, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrC, PAGE_SIZE));
}

static void vm_region_invalid_args() {
  KTEST_BEGIN("vm_verify_region() invalid args");
  int x;
  KEXPECT_EQ(-EINVAL, vm_verify_region(NULL, (addr_t)&x, (addr_t)&x + 10,
                                       0, 0));
  KEXPECT_EQ(-EINVAL, vm_verify_region(proc_current(), (addr_t)&x, (addr_t)&x,
                                       0, 0));
  KEXPECT_EQ(-EINVAL, vm_verify_region(proc_current(), (addr_t)&x,
                                       (addr_t)&x - 1, 0, 0));
}

// TODO(aoates): test PROT_EXEC once it's supported

void vm_test() {
  KTEST_SUITE_BEGIN("VM tests");

  vm_region_basic();
  vm_region_mmap();
  vm_region_mmap_ro();
  vm_region_mmap_hole();
  vm_region_invalid_args();
}
