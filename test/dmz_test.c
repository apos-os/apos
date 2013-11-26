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
#include "memory/memory.h"
#include "memory/mmap.h"
#include "syscall/dmz.h"
#include "test/ktest.h"

static void dmz_buffer_null_buffer(void) {
  KTEST_BEGIN("syscall_verify_buffer() NULL buffer test");

  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(NULL, 10, 0));
}

static void dmz_buffer_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_buffer() basic test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addrA));
  void* const addrAEnd = (void*)((addr_t)addrA + kRegionSize);

  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 0));
  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 1));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrAEnd, kRegionSize, 0));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrAEnd, kRegionSize, 1));

  KTEST_BEGIN("syscall_verify_buffer() overlap region start test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrA - 10), 20, 0));

  KTEST_BEGIN("syscall_verify_buffer() overlap region end test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrAEnd - 10), 20, 0));

  KTEST_BEGIN("syscall_verify_buffer() one past end test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrA, kRegionSize + 1, 0));

  KTEST_BEGIN("syscall_verify_buffer() middle of region test");
  KEXPECT_EQ(0, syscall_verify_buffer(
          (void*)((addr_t)addrA + 10), 20, 0));

  KTEST_BEGIN("syscall_verify_buffer() wraparound address test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(
          (void*)((addr_t)addrA + 200), 0xFFFFFFF0, 0));

  KTEST_BEGIN("syscall_verify_buffer() kernel memory test");
  void* kernel_buf = kmalloc(100);
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(kernel_buf, 10, 0));

  KTEST_BEGIN("syscall_verify_buffer() kernel memory wraparound test");
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(kernel_buf, 0xFFFFFFFE, 0));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void dmz_buffer_read_only(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_buffer() read-only test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_READ | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addrA));

  KEXPECT_EQ(0, syscall_verify_buffer(addrA, kRegionSize, 0));
  KEXPECT_EQ(-EFAULT, syscall_verify_buffer(addrA, kRegionSize, 1));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

static void dmz_string_basic(void) {
  const addr_t kRegionSize = 2 * PAGE_SIZE;

  KTEST_BEGIN("syscall_verify_string() invalid args test");
  KEXPECT_EQ(-EINVAL, syscall_verify_string(NULL));

  KTEST_BEGIN("syscall_verify_string() basic test");
  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addrA));

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
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
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

  KTEST_BEGIN("syscall_verify_ptr_table() invalid args test");
  KEXPECT_EQ(-EINVAL, syscall_verify_ptr_table(NULL));

  KTEST_BEGIN("syscall_verify_ptr_table() basic test");
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kRegionSize, PROT_ALL,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, &addrA));

  ((addr_t*)addrA)[0] = 1;
  ((addr_t*)addrA)[1] = 2;
  ((addr_t*)addrA)[2] = 0x0;
  KEXPECT_EQ(3, syscall_verify_ptr_table(addrA));

  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA - 1));

  KTEST_BEGIN("syscall_verify_ptr_table() zero-length test");
  ((addr_t*)addrA)[0] = 0x0;
  KEXPECT_EQ(1, syscall_verify_ptr_table(addrA));

  KTEST_BEGIN("syscall_verify_ptr_table() full region (unterminated) test");
  kmemset(addrA, 'x', kRegionSize);
  KEXPECT_EQ(-EFAULT, syscall_verify_ptr_table(addrA));

  KTEST_BEGIN("syscall_verify_ptr_table() full region (terminated) test");
  ((addr_t*)addrA)[kRegionSize / sizeof(addr_t) - 1] = 0x0;
  KEXPECT_EQ(kRegionSize / sizeof(addr_t), syscall_verify_ptr_table(addrA));

  KEXPECT_EQ(0, do_munmap(addrA, kRegionSize));
}

// TODO(aoates): test syscall_verify_string() in read-only region.

void dmz_test(void) {
  KTEST_SUITE_BEGIN("Syscall DMZ tests");

  dmz_buffer_null_buffer();
  dmz_buffer_basic();
  dmz_buffer_read_only();

  dmz_string_basic();

  dmz_table_basic();
}
