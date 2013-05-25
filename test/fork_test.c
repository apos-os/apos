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
#include "memory/mmap.h"
#include "proc/fork.h"
#include "proc/sleep.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

// Addresses of various mappings created in the parent and child processes.
#define MAP_LENGTH (3 * PAGE_SIZE)
#define SHARED_MAP_BASE 0x5000
#define PRIVATE_MAP_BASE 0xA000
#define SEPARATE_MAP_BASE 0x10000

#define SHARED_ADDR1 (SHARED_MAP_BASE + 100)
#define SHARED_ADDR2 (SHARED_MAP_BASE + 100 + PAGE_SIZE)
#define SHARED_ADDR3 (SHARED_MAP_BASE + 100 + 2 * PAGE_SIZE)

#define PRIVATE_ADDR1 (PRIVATE_MAP_BASE + 200)
#define PRIVATE_ADDR2 (PRIVATE_MAP_BASE + 200 + PAGE_SIZE)
#define PRIVATE_ADDR3 (PRIVATE_MAP_BASE + 200 + 2 * PAGE_SIZE)

#define SEPARATE_ADDR1 (SEPARATE_MAP_BASE + 300)
#define SEPARATE_ADDR2 (SEPARATE_MAP_BASE + 300 + PAGE_SIZE)
#define SEPARATE_ADDR3 (SEPARATE_MAP_BASE + 300 + 2 * PAGE_SIZE)

static pid_t child_pid = -1;

static void make_separate_mapping() {
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)SEPARATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED,
                        -1, 0, &addr));
}

static void child_func(void* arg) {
  char cwd[VFS_MAX_PATH_LENGTH];
  klogf("child proc:  id: %d  arg: %d\n", proc_current()->id, arg);
  vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH);
  klogf("child proc:  cwd: %s\n", cwd);

  KEXPECT_EQ(child_pid, proc_current()->id);

  KEXPECT_EQ(1, *(uint32_t*)SHARED_ADDR1);
  KEXPECT_EQ(2, *(uint32_t*)SHARED_ADDR2);
  KEXPECT_EQ(3, *(uint32_t*)SHARED_ADDR3);
  KEXPECT_EQ(4, *(uint32_t*)PRIVATE_ADDR1);
  KEXPECT_EQ(5, *(uint32_t*)PRIVATE_ADDR2);
  KEXPECT_EQ(6, *(uint32_t*)PRIVATE_ADDR3);

  // Write some values into the mappings.
  *(uint32_t*)(SHARED_ADDR1) = 10;
  *(uint32_t*)(SHARED_ADDR2) = 20;
  *(uint32_t*)(SHARED_ADDR3) = 30;
  *(uint32_t*)(PRIVATE_ADDR1) = 40;
  *(uint32_t*)(PRIVATE_ADDR2) = 50;
  *(uint32_t*)(PRIVATE_ADDR3) = 60;

  // Make a new mapping that shouldn't be shared in the child.
  make_separate_mapping();
  *(uint32_t*)(SEPARATE_ADDR1) = 70;
  *(uint32_t*)(SEPARATE_ADDR2) = 80;
  *(uint32_t*)(SEPARATE_ADDR3) = 90;

  // Let the parent run.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Make sure we see the new values in the shared mapping, but not in the
  // others.
  KEXPECT_EQ(11, *(uint32_t*)SHARED_ADDR1);
  KEXPECT_EQ(22, *(uint32_t*)SHARED_ADDR2);
  KEXPECT_EQ(33, *(uint32_t*)SHARED_ADDR3);
  KEXPECT_EQ(40, *(uint32_t*)PRIVATE_ADDR1);
  KEXPECT_EQ(50, *(uint32_t*)PRIVATE_ADDR2);
  KEXPECT_EQ(60, *(uint32_t*)PRIVATE_ADDR3);
  KEXPECT_EQ(70, *(uint32_t*)SEPARATE_ADDR1);
  KEXPECT_EQ(80, *(uint32_t*)SEPARATE_ADDR2);
  KEXPECT_EQ(90, *(uint32_t*)SEPARATE_ADDR3);

  KEXPECT_EQ(0, do_munmap((void*)SHARED_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)SEPARATE_MAP_BASE, MAP_LENGTH));

  while (1) {
    ksleep(10000);
  }

  // TODO(aoates): call exit()
}

static void do_test() {
  // Create a shared and a private mapping.
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)SHARED_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED,
                        -1, 0, &addr));
  KEXPECT_EQ(0, do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                        -1, 0, &addr));

  // Write some values into the mappings.
  *(uint32_t*)(SHARED_ADDR1) = 1;
  *(uint32_t*)(SHARED_ADDR2) = 2;
  *(uint32_t*)(SHARED_ADDR3) = 3;
  *(uint32_t*)(PRIVATE_ADDR1) = 4;
  *(uint32_t*)(PRIVATE_ADDR2) = 5;
  *(uint32_t*)(PRIVATE_ADDR3) = 6;

  // Fork.
  pid_t parent_pid = proc_current()->id;
  child_pid = proc_fork(&child_func, (void*)0xABCD);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_NE(parent_pid, child_pid);

  // Make a new mapping that shouldn't be shared in the child.
  make_separate_mapping();
  *(uint32_t*)(SEPARATE_ADDR1) = 7;
  *(uint32_t*)(SEPARATE_ADDR2) = 8;
  *(uint32_t*)(SEPARATE_ADDR3) = 9;

  // Let the child run.
  for (int i = 0; i < 10; ++i) scheduler_yield();

  // Make sure we see the new values in the shared mapping, but not in the
  // others.
  KEXPECT_EQ(10, *(uint32_t*)SHARED_ADDR1);
  KEXPECT_EQ(20, *(uint32_t*)SHARED_ADDR2);
  KEXPECT_EQ(30, *(uint32_t*)SHARED_ADDR3);
  KEXPECT_EQ(4, *(uint32_t*)PRIVATE_ADDR1);
  KEXPECT_EQ(5, *(uint32_t*)PRIVATE_ADDR2);
  KEXPECT_EQ(6, *(uint32_t*)PRIVATE_ADDR3);
  KEXPECT_EQ(7, *(uint32_t*)SEPARATE_ADDR1);
  KEXPECT_EQ(8, *(uint32_t*)SEPARATE_ADDR2);
  KEXPECT_EQ(9, *(uint32_t*)SEPARATE_ADDR3);

  *(uint32_t*)(SHARED_ADDR1) = 11;
  *(uint32_t*)(SHARED_ADDR2) = 22;
  *(uint32_t*)(SHARED_ADDR3) = 33;
  *(uint32_t*)(PRIVATE_ADDR1) = 44;
  *(uint32_t*)(PRIVATE_ADDR2) = 55;
  *(uint32_t*)(PRIVATE_ADDR3) = 66;

  // TODO(aoates): test fd and cwd forking.

  // TODO(aoates): wait for child to exit.

  KEXPECT_EQ(0, do_munmap((void*)SHARED_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)SEPARATE_MAP_BASE, MAP_LENGTH));
}

void fork_test() {
  KTEST_SUITE_BEGIN("proc_fork()");

  KTEST_BEGIN("basic fork() test");
  do_test();
}
