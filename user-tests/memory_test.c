// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include <assert.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <apos/syscall_decls.h>

#include "ktest.h"
#include "all_tests.h"

static void mmap_test(void) {
  KTEST_BEGIN("mmap(): basic private and shared test");
  void* addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  KEXPECT_NE(NULL, addr1);
  *(uint32_t*)addr1 = 0x1234;

  void* addr2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  KEXPECT_NE(NULL, addr2);
  *(uint32_t*)addr2 = 0x5678;

  pid_t child;
  if ((child = fork()) == 0) {
    assert(*(uint32_t*)addr1 == 0x1234);
    assert(*(uint32_t*)addr2 == 0x5678);
    *(uint32_t*)addr1 = 0xabcd;
    *(uint32_t*)addr2 = 0xdcba;
    exit(0);
  }

  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_EQ(0, status);

  KEXPECT_EQ(0xabcd, *(uint32_t*)addr1);
  KEXPECT_EQ(0x5678, *(uint32_t*)addr2);
  KEXPECT_EQ(0, munmap(addr1, 4096));
  KEXPECT_EQ(0, munmap(addr2, 4096));


  KTEST_BEGIN("mmap(): kernel-only mmap test");
  addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS | KMAP_KERNEL_ONLY, -1, 0);
  KEXPECT_NE(NULL, addr1);

  if ((child = fork()) == 0) {
    *(uint32_t*)addr1 = 0xabcd;
    exit(0);
  }

  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));
  KEXPECT_EQ(0, munmap(addr1, 4096));
}

static void mmap_read_errors_test(void) {
  KTEST_BEGIN("error during read of mmap()'d file sends SIGBUS");
  KEXPECT_EQ(0, mkdir("_memory_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, mount("", "_memory_test", "testfs", 0, NULL, 0));

  int fd = open("_memory_test/read_error", O_RDWR);
  KEXPECT_GE(fd, 0);
  char buf[10];
  KEXPECT_ERRNO(EIO, read(fd, buf, 10));

  const size_t kMapLen = 4096;
  void* map = mmap(NULL, kMapLen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  KEXPECT_NE(NULL, map);

  pid_t child = fork();
  if (child == 0) {
    int x = *(int*)map;  // Should generate SIGBUS.
    printf("%d", x);     // Shouldn't get here.
    exit(1);
  }
  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGBUS, WTERMSIG(status));


  KTEST_BEGIN("error during write of mmap()'d file sends SIGBUS");
  child = fork();
  if (child == 0) {
    *(int*)map = 5;  // Should generate SIGBUS.
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGBUS, WTERMSIG(status));


  // As the above tests, but the error is generated in the syscall handling.
  // TODO(aoates): tests that exercise all syscall arg types (buffer, string,
  // string table, r/w buffer, etc).
  KTEST_BEGIN("error during write() from mmap()'d file sends SIGBUS");
  int fd2 = open("_memory_test_dummy_file", O_CREAT | O_RDWR, S_IRWXU);
  KEXPECT_GE(fd2, 0);
  child = fork();
  if (child == 0) {
    int result = write(fd2, map, 5);  // Should generate SIGBUS.
    exit(result);
  }
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGBUS, WTERMSIG(status));


  KTEST_BEGIN("error during read() into mmap()'d file sends SIGBUS");
  child = fork();
  if (child == 0) {
    int result = read(fd2, map, 5);  // Should generate SIGBUS.
    exit(result);
  }
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGBUS, WTERMSIG(status));


  KEXPECT_EQ(0, munmap(map, kMapLen));
  KEXPECT_EQ(0, close(fd));
  KEXPECT_EQ(0, close(fd2));
  KEXPECT_EQ(0, unmount("_memory_test", 0));
  KEXPECT_EQ(0, rmdir("_memory_test"));
  KEXPECT_EQ(0, unlink("_memory_test_dummy_file"));
}

void memory_test(void) {
  KTEST_SUITE_BEGIN("basic memory tests");
  mmap_test();
  mmap_read_errors_test();
}
