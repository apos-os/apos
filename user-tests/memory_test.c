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
#include <sys/wait.h>
#include <unistd.h>

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

void memory_test(void) {
  KTEST_SUITE_BEGIN("basic memory tests");
  mmap_test();
}
