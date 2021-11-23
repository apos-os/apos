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
#include "proc/exit.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static kpid_t child_pid = -1;

static void basic_child_func(void* arg) {
  KEXPECT_EQ(0x1234, (intptr_t)arg);
  char cwd[VFS_MAX_PATH_LENGTH];
  KLOG("child proc:  id: %d  arg: %p\n", proc_current()->id, arg);
  vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH);
  KLOG("child proc:  cwd: %s\n", cwd);

  KEXPECT_EQ(child_pid, proc_current()->id);

  proc_exit(0x5678);
}

static void basic_test(void) {
  KTEST_BEGIN("fork() basic test");

  // Fork.
  kpid_t parent_pid = proc_current()->id;
  child_pid = proc_fork(&basic_child_func, (void*)0x1234);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_NE(parent_pid, child_pid);

  process_t* child_proc = proc_get(child_pid);
  KEXPECT_EQ(&child_proc->children_link,
             proc_current()->children_list.head);
  KEXPECT_EQ(&child_proc->children_link,
             proc_current()->children_list.tail);
  KEXPECT_EQ(proc_current(), child_proc->parent);

  int exit_status = -1;
  const kpid_t child_pid_wait = proc_wait(&exit_status);
  KEXPECT_EQ(child_pid, child_pid_wait);
  KEXPECT_EQ(0x5678, exit_status);
}

static void implicit_exit_child_func(void* arg) {
}

static void implicit_exit_test(void) {
  KTEST_BEGIN("fork() implicit proc_exit() test");

  proc_fork(&implicit_exit_child_func, 0x0);

  int exit_status = -1;
  proc_wait(&exit_status);
  KEXPECT_EQ(0, exit_status);
}

static void parent_exit_first_child_func_inner(void* arg) {
  scheduler_yield();
  scheduler_yield();
  scheduler_yield();
  proc_exit(6);
}

static void parent_exit_first_child_func_outer(void* arg) {
  *(kpid_t*)arg = proc_fork(&parent_exit_first_child_func_inner, 0x0);
  proc_exit(5);
}

static void parent_exit_first_test(void) {
  KTEST_BEGIN("fork() parent exit first test");

  kpid_t inner_pid = 0;
  proc_fork(&parent_exit_first_child_func_outer, &inner_pid);

  int exit_status = -1;
  proc_wait(&exit_status);
  KEXPECT_EQ(5, exit_status);

  // The child should have been adopted by the root process.
  KEXPECT_EQ(0, proc_get(inner_pid)->parent->id);

  for (int i = 0; i < 10; ++i) scheduler_yield();

  KEXPECT_EQ((process_t*)0x0, proc_get(inner_pid));
}

static void reparent_zombie_to_root_inner(void* arg) {
  proc_exit(6);
}

static void reparent_zombie_to_root_outer(void* arg) {
  *(kpid_t*)arg = proc_fork(&reparent_zombie_to_root_inner, 0x0);
  for (int i = 0; i < 3; ++i) scheduler_yield();
  KEXPECT_EQ(PROC_ZOMBIE, proc_get(*(kpid_t*)arg)->state);
  proc_exit(5);
}

static void reparent_zombie_to_root_test(void) {
  KTEST_BEGIN("fork() parent exit reparents zombie children");

  kpid_t inner_pid = 0;
  proc_fork(&reparent_zombie_to_root_outer, &inner_pid);

  int exit_status = -1;
  proc_wait(&exit_status);
  KEXPECT_EQ(5, exit_status);

  // The child should have been adopted by the root process, but it may have
  // already been cleaned up.
  if (proc_get(inner_pid)) {
    KEXPECT_EQ(0, proc_get(inner_pid)->parent->id);
    for (int i = 0; i < 3; ++i) scheduler_yield();
  }

  KEXPECT_EQ((process_t*)0x0, proc_get(inner_pid));
}

static void multi_child_func(void* arg) {
  scheduler_yield();
  scheduler_yield();
  proc_exit((intptr_t)arg);
}

static void multi_child_test(void) {
  const int SIZE = 5;

  KTEST_BEGIN("fork() multi-child test");

  int exited[SIZE];
  for (intptr_t i = 0; i < SIZE; ++i) {
    proc_fork(&multi_child_func, (void*)i);
    exited[i] = 0;
  }

  for (int i = 0; i < SIZE; ++i) {
    int exit_status = -1;
    proc_wait(&exit_status);
    KEXPECT_GE(i, 0);
    KEXPECT_LT(i, SIZE);
    KEXPECT_EQ(0, exited[exit_status]);
    exited[exit_status] = 1;
  }
}

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

static void make_separate_mapping(void) {
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)SEPARATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_ANONYMOUS | KMAP_SHARED,
                        -1, 0, &addr));
}

static void child_func(void* arg) {
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
}

static void mapping_test(void) {
  KTEST_BEGIN("fork() mapping test");
  // Create a shared and a private mapping.
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)SHARED_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_ANONYMOUS | KMAP_SHARED,
                        -1, 0, &addr));
  KEXPECT_EQ(0, do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_ANONYMOUS | KMAP_PRIVATE,
                        -1, 0, &addr));

  // Write some values into the mappings.
  *(uint32_t*)(SHARED_ADDR1) = 1;
  *(uint32_t*)(SHARED_ADDR2) = 2;
  *(uint32_t*)(SHARED_ADDR3) = 3;
  *(uint32_t*)(PRIVATE_ADDR1) = 4;
  *(uint32_t*)(PRIVATE_ADDR2) = 5;
  *(uint32_t*)(PRIVATE_ADDR3) = 6;

  // Fork.
  kpid_t child_pid = proc_fork(&child_func, (void*)0xABCD);
  KEXPECT_GE(child_pid, 0);

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

  proc_wait(0x0);

  KEXPECT_EQ(0, do_munmap((void*)SHARED_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
  KEXPECT_EQ(0, do_munmap((void*)SEPARATE_MAP_BASE, MAP_LENGTH));
}

static void test_child2(void* arg) {
  for (int i = 0; i < 5; ++i) scheduler_yield();
  block_cache_clear_unpinned();
  KEXPECT_EQ(2, *(uint32_t*)(PRIVATE_ADDR1));
  scheduler_wake_all((kthread_queue_t*)arg);
}

static void test_child(void* arg) {
  KEXPECT_EQ(1, *(uint32_t*)(PRIVATE_ADDR1));
  *(uint32_t*)(PRIVATE_ADDR1) = 2;
  proc_fork(&test_child2, arg);
}

static void write_then_exit_child(void* arg) {
  KEXPECT_EQ(1, *(uint32_t*)(PRIVATE_ADDR1));
  *(uint32_t*)(PRIVATE_ADDR1) = 2;
}

static void unpinned_mapping_test(void) {
  KTEST_BEGIN("fork() unpinned mapping test");
  // Create a shared and a private mapping.
  void* addr;
  KEXPECT_EQ(0,
             do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                     KMAP_FIXED | KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addr));

  // Write some values into the mappings, then fork.
  *(uint32_t*)(PRIVATE_ADDR1) = 1;

  kthread_queue_t wait;
  kthread_queue_init(&wait);

  kpid_t child_pid = proc_fork(&test_child, &wait);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_EQ(child_pid, proc_wait(NULL));

  // Let the grandchild run.
  scheduler_wait_on(&wait);

  KEXPECT_EQ(1, *(uint32_t*)(PRIVATE_ADDR1));

  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));


  KTEST_BEGIN("Shadow object cleanup on exit test");
  int fd = vfs_open("_shadow_obj_test", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, MAP_LENGTH));
  KEXPECT_EQ(1, vfs_get_vnode_refcount_for_path("_shadow_obj_test"));
  KEXPECT_EQ(0, do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_PRIVATE, fd, 0, &addr));
  KEXPECT_EQ(2, vfs_get_vnode_refcount_for_path("_shadow_obj_test"));

  // Write some values into the mappings, then fork.
  *(uint32_t*)(PRIVATE_ADDR1) = 1;
  KEXPECT_EQ(3, vfs_get_vnode_refcount_for_path("_shadow_obj_test"));

  child_pid = proc_fork(&write_then_exit_child, NULL);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_EQ(child_pid, proc_wait(NULL));
  KEXPECT_EQ(3, vfs_get_vnode_refcount_for_path("_shadow_obj_test"));
  KEXPECT_EQ(1, *(uint32_t*)(PRIVATE_ADDR1));
  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
  // The refcount shoud be at most 2 --- one for the file descriptor, and maybe
  // one if there's still an (unpinned) page for the file in the block cache.
  KEXPECT_LE(vfs_get_vnode_refcount_for_path("_shadow_obj_test"), 2);
  KEXPECT_GE(vfs_get_vnode_refcount_for_path("_shadow_obj_test"), 1);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_shadow_obj_test"));
}

static void anon_helper1(void* arg) {
  // One that we read first, then write; another we just write.
  KEXPECT_EQ(0, *(uint32_t*)(SHARED_ADDR1));
  *(uint32_t*)(SHARED_ADDR1) = 1;
  *(uint32_t*)(SHARED_ADDR2) = 2;
}

// As above, but test handling of shared anonymous mappings (which potentially
// have the same issue in terms of anonymous pages being dropped).
static void unpinned_anon_mapping_test(void) {
  KTEST_BEGIN("fork() unpinned shared anonymous mapping test");
  void* addr;
  KEXPECT_EQ(0,
             do_mmap((void*)SHARED_MAP_BASE, MAP_LENGTH, PROT_ALL,
                     KMAP_FIXED | KMAP_ANONYMOUS | KMAP_SHARED, -1, 0, &addr));

  kpid_t child_pid = proc_fork(&anon_helper1, NULL);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_EQ(child_pid, proc_wait(NULL));

  // We should still see their writes.
  block_cache_clear_unpinned();
  KEXPECT_EQ(1, *(uint32_t*)(SHARED_ADDR1));
  KEXPECT_EQ(2, *(uint32_t*)(SHARED_ADDR2));
  KEXPECT_EQ(0, do_munmap((void*)SHARED_MAP_BASE, MAP_LENGTH));
}

// TODO(aoates): test fd and cwd forking.

void fork_test(void) {
  KTEST_SUITE_BEGIN("proc_fork()");

  basic_test();
  implicit_exit_test();
  parent_exit_first_test();
  reparent_zombie_to_root_test();
  multi_child_test();
  mapping_test();
  unpinned_mapping_test();
  unpinned_anon_mapping_test();
  block_cache_log_stats();
}
