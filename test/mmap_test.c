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
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "memory/page_alloc.h"
#include "memory/vm_area.h"
#include "proc/process.h"
#include "vfs/vfs.h"
#include "test/ktest.h"

const char kFileA[] = "mmap_fileA";
const char kFileB[] = "mmap_fileB";
const int kTestFilePages = 3;

// Checks that the buffer consists only of the given character, and returns the
// first non-matching character if not.  Otherwise, returns the expected
// character.
static char bufcmp(const void* buf, const char expected, int len) {
  for (int i = 0; i < len; ++i) {
    if (((char*)buf)[i] != expected) {
      return ((char*)buf)[i];
    }
  }
  return expected;
}

static void write_test_file(const char name[], char contents) {
  char buf[PAGE_SIZE];

  int fd = vfs_open(name, VFS_O_RDWR | VFS_O_CREAT);
  for (int page = 0; page < kTestFilePages; ++page) {
    kmemset(buf, contents + page, PAGE_SIZE);
    int bytes_left = PAGE_SIZE;
    while (bytes_left > 0) {
      const int result = vfs_write(fd, buf, bytes_left);
      KASSERT(result > 0);
      bytes_left -= result;
    }
  }
  vfs_close(fd);
}

static void setup_test_files() {
  write_test_file(kFileA, 'A');
  write_test_file(kFileB, 'X');
}

// Expect a given memory map contents for the current process.  Skips any kernel
// mappings.
typedef struct {
  addr_t base;
  addr_t length;
  int fd;  // Mapping for the given fd, or -1 for don't care.
} emmap_t;
static void EXPECT_MMAP(int num_entries, emmap_t expected[]) {
  process_t* proc = proc_current();
  int idx = 0;
  list_link_t* link = proc->vm_area_list.head;
  while (link && idx < num_entries) {
    vm_area_t* area = container_of(link, vm_area_t, vm_proc_list);
    if (area->vm_base > MEM_LAST_USER_MAPPABLE_ADDR) {
      link = link->next;
      continue;
    }

    memobj_t* memobj = 0x0;
    if (expected[idx].fd >= 0) {
      KASSERT(vfs_get_memobj(expected[idx].fd, VFS_O_RDONLY, &memobj) == 0);
    }
    if (area->vm_base != expected[idx].base ||
        area->vm_length != expected[idx].length ||
        (expected[idx].fd >= 0 && area->memobj != memobj)) {
      KEXPECT_EQ(expected[idx].base, area->vm_base);
      KEXPECT_EQ(expected[idx].length, area->vm_length);
      if (expected[idx].fd >= 0) {
        KEXPECT_EQ(memobj, area->memobj);
      }
      klogf("FAILURE:\n expected: <base: 0x%x  len: 0x%x  memobj: 0x%x>\n",
            expected[idx].base, expected[idx].length, memobj);
      klogf(" found:    <base: 0x%x  len: 0x%x  memobj: 0x%x>\n",
            area->vm_base, area->vm_length, area->memobj);
      return;
    }
    link = link->next;
    idx++;
  }

  // Skip any remaining kernel mappings.
  while (link) {
    vm_area_t* area = container_of(link, vm_area_t, vm_proc_list);
    if (area->vm_base > MEM_LAST_USER_MAPPABLE_ADDR) {
      link = link->next;
    } else {
      break;
    }
  }

  // Should have seen exactly num_entries entries, and be at the end of the
  // list.
  KEXPECT_EQ(idx, num_entries);
  KEXPECT_EQ((list_link_t*)0x0, link);
}

// Flush all page mappings in the given range.
static void flush_all_mappings(void* start, int pages) {
  for (int i = 0; i < pages; ++i) {
    page_frame_unmap_virtual((addr_t)start + i * PAGE_SIZE);
  }
}

static void mmap_invalid_args() {
  const char kFile[] = "mmap_file";
  const int fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_CREAT);
  KEXPECT_GE(fd, 0);
  void* addr_out;

  // Not page-aligned length, and offset.
  KTEST_BEGIN("mmap(): unaligned args test");
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, 0x15, PROT_ALL,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                              MAP_SHARED, fd, 0x15, &addr_out));

  KTEST_BEGIN("mmap(): length == 0 test");
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, 0, PROT_ALL,
                              MAP_SHARED, fd, 0, &addr_out));

  KTEST_BEGIN("mmap(): invalid fd test");
  KEXPECT_EQ(-EBADF, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                             MAP_SHARED, -5, 0, &addr_out));
  KEXPECT_EQ(-EBADF, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                             MAP_SHARED, fd + 1, 0, &addr_out));
  KEXPECT_EQ(-EBADF, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                             MAP_SHARED, 532333, 0, &addr_out));

  KTEST_BEGIN("mmap(): invalid prot test");
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_NONE,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_WRITE,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_WRITE | PROT_EXEC,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_WRITE | PROT_READ,
                              MAP_SHARED, fd, 0, &addr_out));

  KTEST_BEGIN("mmap(): invalid flags test");
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                              0, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_WRITE,
                              10, fd, 0, &addr_out));

  EXPECT_MMAP(0, (emmap_t[]){});

  vfs_close(fd);
  vfs_unlink(kFile);
}

static void munmap_invalid_args() {
  KTEST_BEGIN("munmap(): unaligned args test");
  KEXPECT_EQ(-EINVAL, do_munmap((void*)0xABCD, PAGE_SIZE));
  KEXPECT_EQ(-EINVAL, do_munmap((void*)(PAGE_SIZE * 10), 0x15));
}

static void mmap_basic() {
  KTEST_BEGIN("mmap(): basic test");
  setup_test_files();

  // Map both files in.
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  const int fdB = vfs_open(kFileB, VFS_O_RDWR);
  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_NE((void*)0x0, addrA);
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdB, 0, &addrB));
  KEXPECT_NE((void*)0x0, addrB);

  EXPECT_MMAP(2, (emmap_t[]){{0x1000, 0x3000, fdA}, {0x4000, 0x3000, fdB}});

  // Make sure they match.
  KEXPECT_EQ('A', bufcmp(addrA, 'A', PAGE_SIZE));
  KEXPECT_EQ('B', bufcmp((char*)addrA + PAGE_SIZE, 'B', PAGE_SIZE));
  KEXPECT_EQ('C', bufcmp((char*)addrA + 2 * PAGE_SIZE, 'C', PAGE_SIZE));
  KEXPECT_EQ('X', bufcmp(addrB, 'X', PAGE_SIZE));
  KEXPECT_EQ('Y', bufcmp((char*)addrB + PAGE_SIZE, 'Y', PAGE_SIZE));
  KEXPECT_EQ('Z', bufcmp((char*)addrB + 2 * PAGE_SIZE, 'Z', PAGE_SIZE));

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(addrB, kTestFilePages * PAGE_SIZE));

  EXPECT_MMAP(0, (emmap_t[]){});

  vfs_close(fdA);
  vfs_close(fdB);
}

static void map_offset_test() {
  KTEST_BEGIN("mmap(): map offset test");
  setup_test_files();

  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, (kTestFilePages - 1) * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, PAGE_SIZE, &addrA));
  KEXPECT_NE((void*)0x0, addrA);

  KEXPECT_EQ('B', bufcmp(addrA, 'B', PAGE_SIZE));
  KEXPECT_EQ('C', bufcmp((char*)addrA + PAGE_SIZE, 'C', PAGE_SIZE));

  KEXPECT_EQ(0, do_munmap(addrA, (kTestFilePages - 1) * PAGE_SIZE));
  vfs_close(fdA);
}

static void partial_unmap_test() {
  KTEST_BEGIN("mmap(): partial unmap test");
  setup_test_files();

  // Map in 3 pages from fileA.
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_NE((void*)0x0, addrA);

  // Unmap the middle page of the fileA mapping.
  KEXPECT_EQ(0, do_munmap((char*)addrA + PAGE_SIZE, PAGE_SIZE));
  // Verify we can still read the first and last pages.
  KEXPECT_EQ('A', bufcmp(addrA, 'A', PAGE_SIZE));
  KEXPECT_EQ('C', bufcmp((char*)addrA + 2 * PAGE_SIZE, 'C', PAGE_SIZE));

  KTEST_BEGIN("mmap(): unmap with hole test");
  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  vfs_close(fdA);
}

// Run a test where we mmap 3 pages of fileA, then munmap one of the pages, then
// mmap a page from fileB into the hole.
// TODO(aoates): run similar tests with unmap regions > 1 page.
static void run_hole_test(int page_to_unmap, char expected[]) {
  // Map in 3 pages from fileA.
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  const int fdB = vfs_open(kFileB, VFS_O_RDWR);
  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_NE((void*)0x0, addrA);

  // Unmap one page of the fileA mapping.
  KEXPECT_EQ(0, do_munmap((char*)addrA + (page_to_unmap * PAGE_SIZE),
                          PAGE_SIZE));

  // Map the last page of fileB into the hole.
  KEXPECT_EQ(0, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdB, 2 * PAGE_SIZE, &addrB));
  KEXPECT_EQ((char*)addrA + (page_to_unmap * PAGE_SIZE), addrB);

  // Check the contents.
  KEXPECT_EQ(expected[0], bufcmp(addrA, expected[0], PAGE_SIZE));
  KEXPECT_EQ(expected[1],
             bufcmp((char*)addrA + PAGE_SIZE, expected[1], PAGE_SIZE));
  KEXPECT_EQ(expected[2],
             bufcmp((char*)addrA + 2 * PAGE_SIZE, expected[2], PAGE_SIZE));

  // Now flush all mappings and check again, to make sure we split the original
  // area correctly.
  flush_all_mappings(addrA, 3);
  KEXPECT_EQ(expected[0], bufcmp(addrA, expected[0], PAGE_SIZE));
  KEXPECT_EQ(expected[1],
             bufcmp((char*)addrA + PAGE_SIZE, expected[1], PAGE_SIZE));
  KEXPECT_EQ(expected[2],
             bufcmp((char*)addrA + 2 * PAGE_SIZE, expected[2], PAGE_SIZE));

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  vfs_close(fdA);
  vfs_close(fdB);
}

static void map_into_hole_test() {
  setup_test_files();
  KTEST_BEGIN("mmap(): map into hole test (prefix)");
  run_hole_test(0, "ZBC");

  KTEST_BEGIN("mmap(): map into hole test (middle)");
  run_hole_test(1, "AZC");

  KTEST_BEGIN("mmap(): map into hole test (suffix)");
  run_hole_test(2, "ABZ");
}

static void mmap_write_test() {
  KTEST_BEGIN("mmap(): write back test");
  setup_test_files();

  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_NE((void*)0x0, addrA);

  // Write to the middle page.
  kstrcpy((char*)addrA + PAGE_SIZE + 100, "written string");
  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  vfs_close(fdA);

  // Read the file and verify it got written.
  const int fdA2 = vfs_open(kFileA, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_seek(fdA2, PAGE_SIZE + 100, VFS_SEEK_SET));
  char buf[50];
  KEXPECT_EQ(50, vfs_read(fdA2, buf, 50));
  KEXPECT_EQ(0, kmemcmp(buf, "written string\0BBB", 18));

  vfs_close(fdA2);
}

// Test mapping the same file multiple times.
static void mmap_multi_map_test() {
  KTEST_BEGIN("mmap(): multi-map test");
  setup_test_files();

  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA1 = 0x0, *addrA2 = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA1));
  KEXPECT_EQ(0, do_mmap(0x0, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA2));
  KEXPECT_NE((void*)0x0, addrA1);
  KEXPECT_NE((void*)0x0, addrA2);
  KEXPECT_NE(addrA1, addrA2);

  EXPECT_MMAP(2, (emmap_t[]){{0x1000, 0x3000, fdA},
              {0x4000, 0x3000, fdA}});

  // Make sure they match.
  KEXPECT_EQ('A', bufcmp(addrA1, 'A', PAGE_SIZE));
  KEXPECT_EQ('A', bufcmp(addrA2, 'A', PAGE_SIZE));

  // Write to one, make sure it shows up in the other.
  kstrcpy((char*)addrA1 + PAGE_SIZE + 100, "written string");
  KEXPECT_EQ(0, kmemcmp((char*)addrA2 + PAGE_SIZE + 100, "written string", 14));

  // Unmap one, and make sure we can still read the other.
  KEXPECT_EQ(0, do_munmap(addrA1, kTestFilePages * PAGE_SIZE));
  KEXPECT_EQ(0, kmemcmp((char*)addrA2 + PAGE_SIZE + 100, "written string", 14));

  EXPECT_MMAP(1, (emmap_t[]){{0x4000, 0x3000, fdA}});

  KEXPECT_EQ(0, do_munmap(addrA2, kTestFilePages * PAGE_SIZE));
  vfs_close(fdA);
}

static void map_file_mode_test() {
  KTEST_BEGIN("mmap(): file mode test");
  setup_test_files();

  int fdA = vfs_open(kFileA, VFS_O_RDONLY);
  void* addrA = 0x0;
  KEXPECT_EQ(-EACCES,
             do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                     MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_EQ(0,
             do_mmap(0x0, PAGE_SIZE, PROT_READ | PROT_EXEC,
                     MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_EQ(0, do_munmap(addrA, PAGE_SIZE));
  vfs_close(fdA);

  fdA = vfs_open(kFileA, VFS_O_WRONLY);
  KEXPECT_EQ(-EACCES,
             do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                     MAP_SHARED, fdA, 0, &addrA));

  KEXPECT_EQ(-EACCES,
             do_mmap(0x0, PAGE_SIZE, PROT_READ | PROT_EXEC,
                     MAP_SHARED, fdA, 0, &addrA));
  vfs_close(fdA);
}

// Test that a non-NULL addr parameter is used as a hint.
static void addr_hint_test() {
  KTEST_BEGIN("mmap(): addr hint test");

  // Map both files in.
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  const int fdB = vfs_open(kFileB, VFS_O_RDWR);
  void* addrA = 0x0, *addrB = 0x0;
  KEXPECT_EQ(0, do_mmap((void*)0x5000, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_EQ((void*)0x5000, addrA);

  // Test that the hint won't cause an existing mapping to be overwritten.
  KEXPECT_EQ(0, do_mmap((void*)0x6000, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdB, 0, &addrB));
  KEXPECT_EQ((void*)0x8000, addrB);

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(addrB, kTestFilePages * PAGE_SIZE));

  vfs_close(fdA);
  vfs_close(fdB);
}

// Test an unaligned addr hint.
static void unaligned_addr_hint_test() {
  KTEST_BEGIN("mmap(): unaligned addr hint test");

  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA = 0x0;
  KEXPECT_EQ(0, do_mmap((void*)0x5432, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED, fdA, 0, &addrA));
  KEXPECT_EQ((void*)0x5000, addrA);

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));

  vfs_close(fdA);
}

static void map_fixed_test() {
  // Map both files in.
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  const int fdB = vfs_open(kFileB, VFS_O_RDWR);
  void* addrA = 0x0, *addrB = 0x0;

  KTEST_BEGIN("mmap(): unaligned MAP_FIXED test");
  KEXPECT_EQ(-EINVAL,
             do_mmap((void*)0x5432, kTestFilePages * PAGE_SIZE, PROT_ALL,
                     MAP_SHARED | MAP_FIXED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): MAP_FIXED test");
  KEXPECT_EQ(0, do_mmap((void*)0x5000, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED | MAP_FIXED, fdA, 0, &addrA));
  KEXPECT_EQ((void*)0x5000, addrA);

  EXPECT_MMAP(1, (emmap_t[]){{0x5000, 0x3000, fdA}});

  KTEST_BEGIN("mmap(): MAP_FIXED overlapping existing mapping test");
  KEXPECT_EQ(0, do_mmap((void*)0x7000, kTestFilePages * PAGE_SIZE, PROT_ALL,
                        MAP_SHARED | MAP_FIXED, fdB, 0, &addrB));
  KEXPECT_EQ((void*)0x7000, addrB);

  EXPECT_MMAP(2, (emmap_t[]){{0x5000, 0x2000, fdA}, {0x7000, 0x3000, fdB}});

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(addrB, kTestFilePages * PAGE_SIZE));

  vfs_close(fdA);
  vfs_close(fdB);
}

// Test that we can't map and unmap in the kernel's memory region.
static void map_unmap_kernel_memory() {
  const int fdA = vfs_open(kFileA, VFS_O_RDWR);
  void* addrA = 0x0;

  KTEST_BEGIN("mmap(): map in kernel memory (partial/hint)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) - PAGE_SIZE),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): map in kernel memory (partial/fixed)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) - PAGE_SIZE),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED | MAP_FIXED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): map in kernel memory (total/hint)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) + 5 * PAGE_SIZE),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): map in kernel memory (total/fixed)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) + 5 * PAGE_SIZE),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED | MAP_FIXED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): map in kernel memory (overflow/hint)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)addr2page(MEM_LAST_MAPPABLE_ADDR),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): map in kernel memory (overflow/fixed)");
  KEXPECT_EQ(-EINVAL, do_mmap(
          (void*)addr2page(MEM_LAST_MAPPABLE_ADDR),
          10 * PAGE_SIZE, PROT_ALL, MAP_SHARED | MAP_FIXED, fdA, 0, &addrA));

  KTEST_BEGIN("mmap(): unmap in kernel memory (partial)");
  KEXPECT_EQ(-EINVAL, do_munmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) - PAGE_SIZE),
          10 * PAGE_SIZE));

  KTEST_BEGIN("mmap(): unmap in kernel memory (total)");
  KEXPECT_EQ(-EINVAL, do_munmap(
          (void*)(addr2page(MEM_LAST_USER_MAPPABLE_ADDR) + 5 * PAGE_SIZE),
          10 * PAGE_SIZE));

  KTEST_BEGIN("mmap(): unmap in kernel memory (overflow)");
  KEXPECT_EQ(-EINVAL, do_munmap(
          (void*)addr2page(MEM_LAST_MAPPABLE_ADDR),
          10 * PAGE_SIZE));

  EXPECT_MMAP(0, (emmap_t[]){});

  vfs_close(fdA);
}

// TODO(aoates): things to test:
// * where fd mode > requested mapping mode
// * vfs_close() after map (public and private mappings)

void mmap_test() {
  KTEST_SUITE_BEGIN("mmap()/munmap() tests");

  mmap_invalid_args();
  munmap_invalid_args();

  mmap_basic();
  map_offset_test();
  partial_unmap_test();
  map_into_hole_test();
  mmap_write_test();
  mmap_multi_map_test();
  map_file_mode_test();
  addr_hint_test();
  unaligned_addr_hint_test();
  map_fixed_test();
  map_unmap_kernel_memory();

  vfs_unlink(kFileA);
  vfs_unlink(kFileB);
}
