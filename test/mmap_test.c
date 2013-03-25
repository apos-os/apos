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

  // Not page-aligned addr, length, and offset.
  KTEST_BEGIN("mmap(): unaligned args test");
  KEXPECT_EQ(-EINVAL, do_mmap((void*)0xABCD, PAGE_SIZE, PROT_ALL,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, 0x15, PROT_ALL,
                              MAP_SHARED, fd, 0, &addr_out));
  KEXPECT_EQ(-EINVAL, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                              MAP_SHARED, fd, 0x15, &addr_out));

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

  // Make sure they match.
  KEXPECT_EQ('A', bufcmp(addrA, 'A', PAGE_SIZE));
  KEXPECT_EQ('B', bufcmp((char*)addrA + PAGE_SIZE, 'B', PAGE_SIZE));
  KEXPECT_EQ('C', bufcmp((char*)addrA + 2 * PAGE_SIZE, 'C', PAGE_SIZE));
  KEXPECT_EQ('X', bufcmp(addrB, 'X', PAGE_SIZE));
  KEXPECT_EQ('Y', bufcmp((char*)addrB + PAGE_SIZE, 'Y', PAGE_SIZE));
  KEXPECT_EQ('Z', bufcmp((char*)addrB + 2 * PAGE_SIZE, 'Z', PAGE_SIZE));

  KEXPECT_EQ(0, do_munmap(addrA, kTestFilePages * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(addrB, kTestFilePages * PAGE_SIZE));
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

  // Make sure they match.
  KEXPECT_EQ('A', bufcmp(addrA1, 'A', PAGE_SIZE));
  KEXPECT_EQ('A', bufcmp(addrA2, 'A', PAGE_SIZE));

  // Write to one, make sure it shows up in the other.
  kstrcpy((char*)addrA1 + PAGE_SIZE + 100, "written string");
  KEXPECT_EQ(0, kmemcmp((char*)addrA2 + PAGE_SIZE + 100, "written string", 14));

  KEXPECT_EQ(0, do_munmap(addrA1, kTestFilePages * PAGE_SIZE));
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

// TODO(aoates): things to test:
// * overlapping mappings (at start, middle, end)
// * partial unmappings
// * where fd mode > requested mapping mode
// * mapping in kernel memory (full and partial)
// * unmapping in kernel memory (full and partial)
// * offset in file
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

  vfs_unlink(kFileA);
  vfs_unlink(kFileB);
}
