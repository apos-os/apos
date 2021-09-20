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
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "proc/signal/signal.h"
#include "syscall/dmz.h"
#include "test/ktest.h"
#include "vfs/mount.h"
#include "vfs/vfs.h"

static void dmz_buffer_null_buffer(void) {
  KTEST_BEGIN("syscall_verify_buffer() NULL buffer test");

  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(NULL, 10, 0, 0));

  KEXPECT_EQ(0, syscall_verify_buffer(NULL, 10, 0, 1));
  KEXPECT_EQ(0, syscall_verify_buffer(NULL, 0, 0, 1));

  KEXPECT_EQ(0, syscall_verify_buffer(NULL, 10, 1, 1));
  KEXPECT_EQ(0, syscall_verify_buffer(NULL, 0, 1, 1));
}

static void dmz_buffer_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_buffer() basic test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));
  void* const addrAEnd = (void*)((addr_t)addrA + kRegionSize);

  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 0, 0));
  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 1, 0));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrAEnd, kRegionSize, 0, 0));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrAEnd, kRegionSize, 1, 0));

  KTEST_BEGIN("syscall_verify_buffer() overlap region start test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrA - 10), 20, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() overlap region end test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrAEnd - 10), 20, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() one past end test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrA, kRegionSize + 1, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() middle of region test");
  KEXPECT_EQ(0, syscall_verify_buffer(
          (void*)((addr_t)addrA + 10), 20, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() wraparound address test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrA + 200), 0xFFFFFFF0, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() kernel memory test");
  void* kernel_buf = kmalloc(100);
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(kernel_buf, 10, 0, 0));

  KTEST_BEGIN("syscall_verify_buffer() kernel memory wraparound test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(kernel_buf, 0xFFFFFFFE, 0, 0));

  kfree(kernel_buf);
  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void dmz_buffer_read_only(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_buffer() read-only test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, KPROT_READ | KPROT_EXEC,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));

  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 0, 0));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrA, kRegionSize, 1, 0));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void dmz_string_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_string() invalid args test");
  KEXPECT_EQ(-EINVAL, syscall_verify_string(NULL));

  KTEST_BEGIN("syscall_verify_string() basic test");
  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));

  kstrcpy(addrA, "test");
  KEXPECT_EQ(5, syscall_verify_string(addrA));

  KEXPECT_EQ(-EFAULT, syscall_verify_string(addrA - 1));

  KTEST_BEGIN("syscall_verify_string() zero-length test");
  *(char*)addrA = '\0';
  KEXPECT_EQ(1, syscall_verify_string(addrA));

  KTEST_BEGIN("syscall_verify_string() full region (unterminated) test");
  kmemset(addrA, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_string(addrA));

  KTEST_BEGIN("syscall_verify_string() full region (terminated) test");
  *(char*)(addrA + kRegionSize - 1) = '\0';
  KEXPECT_EQ(kRegionSize, syscall_verify_string(addrA));

  KTEST_BEGIN("syscall_verify_string() cross-region region test");
  KEXPECT_EQ(0, do_mmap(addrA + kRegionSize, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE | KMAP_FIXED,
                        -1, 0, &addrB));
  kmemset(addrA, 'x', kRegionSize);
  kmemset(addrB, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_string(addrA));

  KTEST_BEGIN("syscall_verify_string() cross-region (terminated) test");
  *(char*)(addrB + kRegionSize - 1) = '\0';
  KEXPECT_EQ(2 * kRegionSize, syscall_verify_string(addrA));

  KTEST_BEGIN("syscall_verify_string() cross-region (partial) test");
  *(char*)(addrB + 99) = '\0';
  KEXPECT_EQ(150, syscall_verify_string(addrA + kRegionSize - 50));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
  KEXPECT_EQ(0, do_munmap(addrB, kRegionSize));
}

static void dmz_table_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;
  const bool is64bit = (sizeof(addr_t) == 8);

  KTEST_BEGIN("syscall_verify_ptr_table() invalid args test");
  KEXPECT_EQ(-EINVAL, syscall_verify_ptr_table(NULL, is64bit));

  KTEST_BEGIN("syscall_verify_ptr_table() basic test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));

  ((addr_t*)addrA)[0] = 1;
  ((addr_t*)addrA)[1] = 2;
  ((addr_t*)addrA)[2] = 0x0;
  KEXPECT_EQ(3, syscall_verify_ptr_table(addrA, is64bit));

  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 1, is64bit));

  KTEST_BEGIN("syscall_verify_ptr_table() zero-length test");
  ((addr_t*)addrA)[0] = 0x0;
  KEXPECT_EQ(1, syscall_verify_ptr_table(addrA, is64bit));

  KTEST_BEGIN("syscall_verify_ptr_table() full region (unterminated) test");
  kmemset(addrA, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA, is64bit));

  KTEST_BEGIN("syscall_verify_ptr_table() full region (terminated) test");
  ((addr_t*)addrA)[kRegionSize / sizeof(addr_t) - 1] = 0x0;
  KEXPECT_EQ(kRegionSize / sizeof(addr_t),
             syscall_verify_ptr_table(addrA, is64bit));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void dmz_table_different_ptr_size(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_ptr_table() basic test [32-bit]");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));

  ((addr32_t*)addrA)[0] = 1;
  ((addr32_t*)addrA)[1] = 2;
  ((addr32_t*)addrA)[2] = 0x80000000;
  ((addr32_t*)addrA)[3] = 0x0;
  KEXPECT_EQ(4, syscall_verify_ptr_table(addrA, false));

  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 1, false));

  KTEST_BEGIN("syscall_verify_ptr_table() zero-length test [32-bit]");
  ((addr32_t*)addrA)[0] = 0x0;
  KEXPECT_EQ(1, syscall_verify_ptr_table(addrA, false));

  KTEST_BEGIN(
      "syscall_verify_ptr_table() full region (unterminated) test [32-bit]");
  kmemset(addrA, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA, false));

  KTEST_BEGIN(
      "syscall_verify_ptr_table() full region (terminated) test [32-bit]");
  ((addr32_t*)addrA)[kRegionSize / sizeof(addr32_t) - 1] = 0x0;
  KEXPECT_EQ(kRegionSize / sizeof(addr32_t),
             syscall_verify_ptr_table(addrA, false));

  // Test 64-bit.
  KTEST_BEGIN("syscall_verify_ptr_table() basic test [64-bit]");
  kmemset(addrA, 0, 2 * PAGE_SIZE);
  ((addr64_t*)addrA)[0] = 1;
  ((addr64_t*)addrA)[1] = 2;
  ((addr64_t*)addrA)[2] = 0x00020000;
  ((addr64_t*)addrA)[3] = 0x80000000;
  ((addr64_t*)addrA)[4] = 0x0000000100000000;
  ((addr64_t*)addrA)[5] = 0x8000000000000000;
  ((addr64_t*)addrA)[6] = 3;
  ((addr64_t*)addrA)[7] = 0x0;
  KEXPECT_EQ(8, syscall_verify_ptr_table(addrA, true));

  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 1, true));
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 4, true));
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 8, true));

  KTEST_BEGIN("syscall_verify_ptr_table() zero-length test [64-bit]");
  ((addr64_t*)addrA)[0] = 0x0;
  KEXPECT_EQ(1, syscall_verify_ptr_table(addrA, true));

  KTEST_BEGIN(
      "syscall_verify_ptr_table() full region (unterminated) test [64-bit]");
  kmemset(addrA, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA, true));

  KTEST_BEGIN(
      "syscall_verify_ptr_table() full region (terminated) test [64-bit]");
  ((addr64_t*)addrA)[kRegionSize / sizeof(addr64_t) - 1] = 0x0;
  KEXPECT_EQ(kRegionSize / sizeof(addr64_t),
             syscall_verify_ptr_table(addrA, true));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

// TODO(aoates): test syscall_verify_string() in read-only region.

static void dmz_copy_from_user_test(void) {
  const addr_t kRegionSize = 3 * PAGE_SIZE;

  KTEST_BEGIN("syscall_copy_from_user(): basic test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addrA));

  char* dst_buf = (char*)kmalloc(kRegionSize);
  uint32_t seed = 12345;
  for (size_t i = 0; i < kRegionSize / sizeof(uint32_t); ++i) {
    seed = fnv_hash(seed);
    ((uint32_t*)addrA)[i] = seed;
  }

  // Basic test --- full copy, page-aligned.
  KEXPECT_EQ(0, syscall_copy_from_user(addrA, dst_buf, kRegionSize));
  KEXPECT_EQ(0, kmemcmp(addrA, dst_buf, kRegionSize));

  // Test less than one page, and offset.
  kmemset(dst_buf, 0, kRegionSize);
  KEXPECT_EQ(0, syscall_copy_from_user(addrA + 50, dst_buf, 100));
  KEXPECT_EQ(0, kmemcmp(addrA + 50, dst_buf, 100));

  // Test spanning 2 pages.
  kmemset(dst_buf, 0, kRegionSize);
  KEXPECT_EQ(0, syscall_copy_from_user(addrA + 50, dst_buf, PAGE_SIZE + 200));
  KEXPECT_EQ(0, kmemcmp(addrA + 50, dst_buf, PAGE_SIZE + 200));
  KEXPECT_EQ(0, dst_buf[PAGE_SIZE + 200]);

  // Test spanning 2 pages, ending on page boundary.
  kmemset(dst_buf, 0, kRegionSize);
  KEXPECT_EQ(0,
             syscall_copy_from_user(addrA + 50, dst_buf, 2 * PAGE_SIZE - 50));
  KEXPECT_EQ(0, kmemcmp(addrA + 50, dst_buf, 2 * PAGE_SIZE - 50));
  KEXPECT_EQ(0, dst_buf[2 * PAGE_SIZE - 50]);

  // Test partial last page.
  kmemset(dst_buf, 0, kRegionSize);
  KEXPECT_EQ(0, syscall_copy_from_user(addrA + 2 * PAGE_SIZE + 50, dst_buf,
                                       PAGE_SIZE - 50));
  KEXPECT_EQ(0, kmemcmp(addrA + 2 * PAGE_SIZE + 50, dst_buf, PAGE_SIZE - 50));
  KEXPECT_EQ(0, dst_buf[PAGE_SIZE - 50]);

  // Test spanning 3 pages
  kmemset(dst_buf, 0, kRegionSize);
  KEXPECT_EQ(0,
             syscall_copy_from_user(addrA + 50, dst_buf, 3 * PAGE_SIZE - 200));
  KEXPECT_EQ(0, kmemcmp(addrA + 50, dst_buf, 3 * PAGE_SIZE - 200));
  KEXPECT_EQ(0, dst_buf[3 * PAGE_SIZE - 200]);


  KTEST_BEGIN("syscall_copy_from_user(): goes outside mapped area");
  KEXPECT_EQ(-EFAULT,
             syscall_copy_from_user(addrA, dst_buf, 3 * PAGE_SIZE + 1));
  // TODO(aoates): this should generate SIGSEV, I think.
  KEXPECT_EQ(-EFAULT, syscall_copy_from_user(addrA + 2 * PAGE_SIZE + 50,
                                             dst_buf, PAGE_SIZE));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));


  KTEST_BEGIN("syscall_copy_from_user(): error paging in");
  KEXPECT_EQ(0, vfs_mkdir("_dmz_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mount("", "_dmz_test", "testfs", 0, NULL, 0));
  int fd = vfs_open("_dmz_test/read_error", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(
      0, do_mmap(NULL, kRegionSize, MEM_PROT_ALL, KMAP_PRIVATE, fd, 0, &addrA));

  KEXPECT_EQ(-EIO, syscall_copy_from_user(addrA, dst_buf, 100));
  ksigset_t pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGBUS));
  proc_suppress_signal(proc_current(), SIGBUS);

  KEXPECT_EQ(-EIO, syscall_copy_from_user(addrA + 50, dst_buf, PAGE_SIZE));
  pending = proc_pending_signals(proc_current());
  KEXPECT_TRUE(ksigismember(&pending, SIGBUS));
  proc_suppress_signal(proc_current(), SIGBUS);


  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
  KEXPECT_EQ(0, vfs_unmount("_dmz_test", 0));
  KEXPECT_EQ(0, vfs_rmdir("_dmz_test"));

  kfree(dst_buf);
}

void dmz_test(void) {
  KTEST_SUITE_BEGIN("Syscall DMZ tests");

  dmz_buffer_null_buffer();
  dmz_buffer_basic();
  dmz_buffer_read_only();

  dmz_string_basic();

  dmz_table_basic();
  dmz_table_different_ptr_size();

  dmz_copy_from_user_test();
}
