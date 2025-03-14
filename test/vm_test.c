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
#include "proc/signal/signal.h"
#include "test/ktest.h"
#include "vfs/mount.h"
#include "vfs/vfs.h"

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


static void EXPECT_ADDRESS_ONE(addr_t start, addr_t end,
                               int expected_result,
                               int is_write, int is_user) {
  addr_t end_out = 0;
  KEXPECT_EQ(expected_result,
             vm_verify_address(proc_current(), start,
                               is_write, is_user, &end_out));
  if (expected_result == 0)
    KEXPECT_EQ(end, end_out);
  else
    KEXPECT_EQ(start, end_out);
}

static void EXPECT_ADDRESS(addr_t start, addr_t end,
                           int kernel_read, int kernel_write,
                           int user_read, int user_write) {
  EXPECT_ADDRESS_ONE(start, end, kernel_read, 0, 0);
  EXPECT_ADDRESS_ONE(start, end, kernel_write, 1, 0);
  EXPECT_ADDRESS_ONE(start, end, user_read, 0, 1);
  EXPECT_ADDRESS_ONE(start, end, user_write, 1, 1);
}

static void vm_region_basic(void) {
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

static void vm_region_mmap(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d R/W region");

  void* addr = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addr));

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

static void vm_region_mmap_ro(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d R/O region");

  void* addr = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, KPROT_READ | KPROT_EXEC,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addr));

  EXPECT_REGION((addr_t)addr, (addr_t)addr + kRegionSize,
                0, -EFAULT, 0, -EFAULT);

  KEXPECT_EQ(0, do_munmap(addr, kRegionSize));
}

// Map two regions with a hole in the middle.
static void vm_region_mmap_hole(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_region() mmap()'d regions with hole");

  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize + PAGE_SIZE, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE | KMAP_FIXED,
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
                        KPROT_READ | KPROT_EXEC,
                        KMAP_ANONYMOUS | KMAP_PRIVATE | KMAP_FIXED,
                        -1, 0, &addrC));

  // Should be able to read across the whole region, but not write.
  EXPECT_REGION((addr_t)addrA, (addr_t)addrB + kRegionSize,
                0, -EFAULT, 0, -EFAULT);

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrB, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrC, PAGE_SIZE));
}

static void vm_region_invalid_args(void) {
  KTEST_BEGIN("vm_verify_region() invalid args");
  int x;
  KEXPECT_EQ(-EINVAL, vm_verify_region(NULL, (addr_t)&x, (addr_t)&x + 10,
                                       0, 0));
  KEXPECT_EQ(-EINVAL, vm_verify_region(proc_current(), (addr_t)&x, (addr_t)&x,
                                       0, 0));
  KEXPECT_EQ(-EINVAL, vm_verify_region(proc_current(), (addr_t)&x,
                                       (addr_t)&x - 1, 0, 0));
}

static void vm_address_basic(void) {
  KTEST_BEGIN("vm_verify_address() kernel heap");
  void* heap = kmalloc(10);
  addr_t end_out = 0;
  KEXPECT_EQ(0,
             vm_verify_address(proc_current(), (addr_t)heap, 0, 0, &end_out));
  KEXPECT_GE(end_out, (addr_t)heap + 10);

  end_out = 0;
  KEXPECT_EQ(0,
             vm_verify_address(proc_current(), (addr_t)heap, 1, 0, &end_out));
  KEXPECT_GE(end_out, (addr_t)heap + 10);

  end_out = 0;
  KEXPECT_EQ(-EFAULT,
             vm_verify_address(proc_current(), (addr_t)heap, 0, 1, &end_out));
  KEXPECT_EQ((addr_t)heap, end_out);

  end_out = 0;
  KEXPECT_EQ(-EFAULT,
             vm_verify_address(proc_current(), (addr_t)heap, 1, 1, &end_out));
  KEXPECT_EQ((addr_t)heap, end_out);
  kfree(heap);

  KTEST_BEGIN("vm_verify_address() kernel code");
  // TODO(aoates): test kernel access to code when we have a mapping for it.
  end_out = 0;
  KEXPECT_EQ(-EFAULT,
             vm_verify_address(proc_current(), (addr_t)&do_mmap, 0, 1,
                               &end_out));
  KEXPECT_EQ((addr_t)&do_mmap, end_out);

  end_out = 0;
  KEXPECT_EQ(-EFAULT,
             vm_verify_address(proc_current(), (addr_t)&do_mmap, 1, 1,
                               &end_out));
  KEXPECT_EQ((addr_t)&do_mmap, end_out);
}

static void vm_address_mmap_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("vm_verify_address() basic");

  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));
  EXPECT_ADDRESS((addr_t)addrA, (addr_t)addrA + kRegionSize,
                 0, 0, 0, 0);

  KTEST_BEGIN("vm_verify_address() middle of region");
  EXPECT_ADDRESS((addr_t)addrA + 200, (addr_t)addrA + kRegionSize,
                 0, 0, 0, 0);

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void vm_address_mmap_ro(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("vm_verify_address() R/O region");

  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, KPROT_READ | KPROT_EXEC,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));
  EXPECT_ADDRESS((addr_t)addrA, (addr_t)addrA + kRegionSize,
                 0, -EFAULT, 0, -EFAULT);

  KTEST_BEGIN("vm_verify_address() middle of R/O region");
  EXPECT_ADDRESS((addr_t)addrA + 200, (addr_t)addrA + kRegionSize,
                 0, -EFAULT, 0, -EFAULT);

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void vm_address_mmap_hole(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  KTEST_BEGIN("vm_verify_address() mmap()'d regions with hole");

  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize + PAGE_SIZE, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE | KMAP_FIXED,
                        -1, 0, &addrB));

  EXPECT_ADDRESS((addr_t)addrA, (addr_t)addrA + kRegionSize,
                 0, 0, 0, 0);

  EXPECT_ADDRESS((addr_t)addrB, (addr_t)addrB + kRegionSize,
                 0, 0, 0, 0);

  // Test in hole.
  EXPECT_ADDRESS((addr_t)addrA + kRegionSize + 20,
                 (addr_t)addrA + kRegionSize + 20,
                 -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  // Test for off-by-ones when handling the first and last address of a region.
  KTEST_BEGIN("vm_verify_address() last address of region");
  EXPECT_ADDRESS((addr_t)addrA + kRegionSize,
                 (addr_t)addrA + kRegionSize,
                 -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  KTEST_BEGIN("vm_verify_address() one before first address of region");
  EXPECT_ADDRESS((addr_t)addrB -1,
                 (addr_t)addrB -1,
                 -EFAULT, -EFAULT, -EFAULT, -EFAULT);

  // Now map a R/O area into the hole.
  KTEST_BEGIN("vm_verify_address() mmap()'d regions with R/O middle region");
  void* addrC = 0x0;
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize, PAGE_SIZE,
                        KPROT_READ | KPROT_EXEC,
                        KMAP_ANONYMOUS | KMAP_PRIVATE | KMAP_FIXED,
                        -1, 0, &addrC));

  KTEST_BEGIN("vm_verify_address() across read-only hole (read)");
  EXPECT_ADDRESS_ONE((addr_t)addrA, (addr_t)addrB + kRegionSize,
                     0, 0, 0);

  KTEST_BEGIN("vm_verify_address() across read-only hole (write)");
  EXPECT_ADDRESS_ONE((addr_t)addrA, (addr_t)addrA + kRegionSize,
                     0, 1, 0);

  KTEST_BEGIN("vm_verify_address() inside read-only hole (read) (#1)");
  EXPECT_ADDRESS_ONE((addr_t)addrC, (addr_t)addrB + kRegionSize,
                     0, 0, 0);

  KTEST_BEGIN("vm_verify_address() inside read-only hole (read) (#2)");
  EXPECT_ADDRESS_ONE((addr_t)addrC + 200, (addr_t)addrB + kRegionSize,
                     0, 0, 0);

  KTEST_BEGIN("vm_verify_address() across read-only hole (write) (#1)");
  EXPECT_ADDRESS_ONE((addr_t)addrC, (addr_t)addrA + kRegionSize,
                     -EFAULT, 1, 0);

  KTEST_BEGIN("vm_verify_address() across read-only hole (write) (#2)");
  EXPECT_ADDRESS_ONE((addr_t)addrC + 200, (addr_t)addrA + kRegionSize,
                     -EFAULT, 1, 0);

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrB, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrC, PAGE_SIZE));
}

static void vm_address_invalid_args(void) {
  KTEST_BEGIN("vm_verify_address() invalid args");
  int x;
  addr_t end_out;
  KEXPECT_EQ(-EINVAL, vm_verify_address(NULL, (addr_t)&x, 0, 0, &end_out));
  KEXPECT_EQ(-EINVAL,
             vm_verify_address(proc_current(), (addr_t)&x, 0, 0, NULL));
}

static void vm_resolve_test(void) {
  KTEST_BEGIN("vm_resolve_address(): invalid args");
  int x;
  phys_addr_t resolved, resolved2;
  bc_entry_t* entry = NULL;
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(NULL, (addr_t)&x, 4, 0, 0, &entry, &resolved));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(), (addr_t)&x, 4, 0, 0,
                                         &entry, NULL));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(), (addr_t)&x, 3, 0, 0,
                                         &entry, &resolved));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(), (addr_t)&x, 5, 0, 0,
                                         &entry, &resolved));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(), (addr_t)&x, 12, 0, 0,
                                         &entry, &resolved));

  KTEST_BEGIN("vm_resolve_address(): basic");
  void* mmaped_addr = NULL;
  // Map three pages, then unmap the third .
  KEXPECT_EQ(0, do_mmap(NULL, 3 * PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_PRIVATE | KMAP_ANONYMOUS, -1, 0, &mmaped_addr));
  KEXPECT_EQ(
      0, do_munmap((void*)((addr_t)mmaped_addr + 2 * PAGE_SIZE), PAGE_SIZE));

  // At first, the page isn't mapped; the blocking call below should page it in.
  KEXPECT_EQ(0,
             vm_resolve_address_noblock(proc_current(), (addr_t)mmaped_addr, 4,
                                        /*is_write=*/false,
                                        /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(NULL, entry);
  KEXPECT_EQ(0,
             vm_resolve_address_noblock(proc_current(), (addr_t)mmaped_addr, 4,
                                        /*is_write=*/false,
                                        /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(NULL, entry);

  // This should trigger paging in.
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_NE(NULL, entry);
  KEXPECT_EQ(resolved, entry->block_phys);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));

  KEXPECT_EQ(0, *(uint32_t*)mmaped_addr);

  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr + 4, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(resolved + 4, resolved2);
  KEXPECT_NE(NULL, entry);
  KEXPECT_EQ(resolved2, entry->block_phys + 4);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 1,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(resolved, resolved2);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 2,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(resolved, resolved2);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 8,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(resolved, resolved2);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  entry = NULL;
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 3,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(NULL, entry);
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 5,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 6,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 7,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 9,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 16,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved2));
  ksigset_t pending;
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr + 2 * PAGE_SIZE, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));
  // No signal should be generated --- not a user access.
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));

  // Last address on first page.
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE - 1, 1,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_NE(NULL, entry);
  KEXPECT_EQ(resolved, entry->block_phys + PAGE_SIZE - 1);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE - 4, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));

  *(uint32_t*)(mmaped_addr + PAGE_SIZE + 64) = 0x5678;
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE + 64, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_NE(NULL, entry);
  KEXPECT_EQ(resolved, entry->block_phys + 64);
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));

  KEXPECT_EQ(0x5678, *(uint32_t*)(phys2virt(resolved)));

  // Last address on second page.
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + 2 * PAGE_SIZE - 1, 1,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + 2 * PAGE_SIZE - 4, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));

  // Test is_write = 1.
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE + 64, 4,
                                   /*is_write=*/true,
                                   /*is_user=*/false, &entry, &resolved2));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(resolved, resolved2);

  KTEST_BEGIN("vm_resolve_address(): unaligned accesses");
  KEXPECT_EQ(-EINVAL,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr + 2, 4,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE - 4, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  // EFAULT could also be returned here.
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr + PAGE_SIZE - 2, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr + PAGE_SIZE - 4, 8,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(-EINVAL, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr + PAGE_SIZE - 3, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));


  KTEST_BEGIN("vm_resolve_address(): access to invalid (unmapped) address");
  void* invalid_addr = NULL;
  KEXPECT_EQ(0, do_mmap(NULL, 3 * PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_PRIVATE | KMAP_ANONYMOUS, -1, 0, &invalid_addr));
  KEXPECT_EQ(0, do_munmap(invalid_addr, 3 * PAGE_SIZE));
  KEXPECT_EQ(-EFAULT,
             vm_resolve_address(proc_current(), (addr_t)invalid_addr, 4,
                                /*is_write=*/false,
                                /*is_user=*/false, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));
  KEXPECT_EQ(-EFAULT,
             vm_resolve_address(proc_current(), (addr_t)invalid_addr, 4,
                                /*is_write=*/false,
                                /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);


  KTEST_BEGIN("vm_resolve_address(): access to kernel heap");
  // N.B.: in theory this could be allowed, but we don't track these mappings so
  // can't resolve to a physical address.
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(), (addr_t)&x, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(), (addr_t)&x, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);
  void* heap = kmalloc(10);
  addr_t aligned_heap_addr = ((addr_t)heap & ~0x3) + 4;
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(), aligned_heap_addr, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/false, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(), aligned_heap_addr, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);
  kfree(heap);

  KTEST_BEGIN("vm_resolve_address(): user access to kernel mappings");
  void* mmaped_addr_kernel_only = NULL;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_PRIVATE | KMAP_ANONYMOUS | KMAP_KERNEL_ONLY, -1, 0,
                        &mmaped_addr_kernel_only));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(),
                                   (addr_t)mmaped_addr + PAGE_SIZE - 4, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/true, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  *(uint32_t*)mmaped_addr_kernel_only = 0;
  KEXPECT_EQ(
      0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr_kernel_only, 4,
                            /*is_write=*/false,
                            /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr_kernel_only, 4,
                                         /*is_write=*/false,
                                         /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);
  KEXPECT_EQ(-EFAULT, vm_resolve_address(proc_current(),
                                         (addr_t)mmaped_addr_kernel_only, 4,
                                         /*is_write=*/true,
                                         /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);
  KEXPECT_EQ(0, do_munmap(mmaped_addr_kernel_only, PAGE_SIZE));

  KTEST_BEGIN("vm_resolve_address(): write not allowed in read-only mapping");
  void* mmaped_addr_ro = NULL;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_READ,
                        KMAP_PRIVATE | KMAP_ANONYMOUS, -1, 0, &mmaped_addr_ro));
  *(volatile uint32_t*)mmaped_addr_ro;  // Force page-in.
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr_ro, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/false, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(-EFAULT,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr_ro, 4,
                                /*is_write=*/true,
                                /*is_user=*/false, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_FALSE(ksigismember(&pending, SIGSEGV));
  KEXPECT_EQ(0, vm_resolve_address(proc_current(), (addr_t)mmaped_addr_ro, 4,
                                   /*is_write=*/false,
                                   /*is_user=*/true, &entry, &resolved));
  KEXPECT_EQ(0, block_cache_put(entry, BC_FLUSH_NONE));
  KEXPECT_EQ(-EFAULT,
             vm_resolve_address(proc_current(), (addr_t)mmaped_addr_ro, 4,
                                /*is_write=*/true,
                                /*is_user=*/true, &entry, &resolved));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGSEGV));
  proc_suppress_signal(proc_current(), SIGSEGV);

  // Cleanup
  KEXPECT_EQ(0, do_munmap(mmaped_addr, 2 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(mmaped_addr_ro, PAGE_SIZE));
}

static void vm_resolve_test2(void) {
  KTEST_BEGIN("vm_resolve_address(): unable to page in");
  KEXPECT_EQ(0, vfs_mkdir("_resolve_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mount("", "_resolve_test", "testfs", 0, NULL, 0));
  phys_addr_t resolved;
  bc_entry_t* entry = NULL;

  int fd = vfs_open("_resolve_test/read_error", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  void* mmaped_addr = NULL;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_ALL, KMAP_PRIVATE, fd, 0,
                        &mmaped_addr));

  KEXPECT_EQ(-EIO, vm_resolve_address(proc_current(), (addr_t)mmaped_addr, 4,
                                      /*is_write=*/false,
                                      /*is_user=*/true, &entry, &resolved));
  ksigset_t pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGBUS));
  proc_suppress_signal(proc_current(), SIGBUS);
  KEXPECT_EQ(NULL, entry);

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, do_munmap(mmaped_addr, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_unmount("_resolve_test", 0));
  KEXPECT_EQ(0, vfs_rmdir("_resolve_test"));
}

// TODO(aoates): test KPROT_EXEC once it's supported

void vm_test(void) {
  KTEST_SUITE_BEGIN("VM tests");

  vm_region_basic();
  vm_region_mmap();
  vm_region_mmap_ro();
  vm_region_mmap_hole();
  vm_region_invalid_args();

  vm_address_basic();
  vm_address_mmap_basic();
  vm_address_mmap_ro();
  vm_address_mmap_hole();
  vm_address_invalid_args();

  vm_resolve_test();
  vm_resolve_test2();
}
