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
#include "memory/memobj_shadow.h"
#include "memory/mmap.h"
#include "memory/vm.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
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
  KEXPECT_EQ(PROC_ZOMBIE, proc_state(*(kpid_t*)arg));
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
#define MAP_LENGTH (6 * PAGE_SIZE)
#define SHARED_MAP_BASE 0x5000
#define PRIVATE_MAP_BASE 0x15000
#define SEPARATE_MAP_BASE 0x25000

#define SHARED_ADDR1 (SHARED_MAP_BASE + 100)
#define SHARED_ADDR2 (SHARED_MAP_BASE + 100 + PAGE_SIZE)
#define SHARED_ADDR3 (SHARED_MAP_BASE + 100 + 2 * PAGE_SIZE)

#define PRIVATE_ADDR1_OFF 200
#define PRIVATE_ADDR1 (PRIVATE_MAP_BASE + PRIVATE_ADDR1_OFF)
#define PRIVATE_ADDR2_OFF (200 + PAGE_SIZE)
#define PRIVATE_ADDR2 (PRIVATE_MAP_BASE + PRIVATE_ADDR2_OFF)
#define PRIVATE_ADDR3_OFF (200 + 2 * PAGE_SIZE)
#define PRIVATE_ADDR3 (PRIVATE_MAP_BASE + PRIVATE_ADDR3_OFF)
#define PRIVATE_ADDR4 (PRIVATE_MAP_BASE + 200 + 3 * PAGE_SIZE)
#define PRIVATE_ADDR5 (PRIVATE_MAP_BASE + 200 + 4 * PAGE_SIZE)
#define PRIVATE_ADDR6 (PRIVATE_MAP_BASE + 200 + 5 * PAGE_SIZE)

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
  KEXPECT_EQ(11, *(uint32_t*)PRIVATE_ADDR4);
  KEXPECT_EQ(12, *(uint32_t*)PRIVATE_ADDR5);

  // Write some values into the mappings.
  *(uint32_t*)(SHARED_ADDR1) = 10;
  *(uint32_t*)(SHARED_ADDR2) = 20;
  *(uint32_t*)(SHARED_ADDR3) = 30;
  *(uint32_t*)(PRIVATE_ADDR1) = 40;
  *(uint32_t*)(PRIVATE_ADDR2) = 50;
  *(uint32_t*)(PRIVATE_ADDR3) = 60;
  *(uint32_t*)(PRIVATE_ADDR5) = 120;

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
  KEXPECT_EQ(11, *(uint32_t*)PRIVATE_ADDR4);
  KEXPECT_EQ(120, *(uint32_t*)PRIVATE_ADDR5);
  KEXPECT_EQ(13, *(uint32_t*)PRIVATE_ADDR6);
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
  *(uint32_t*)(PRIVATE_ADDR4) = 11;
  *(uint32_t*)(PRIVATE_ADDR5) = 12;
  *(uint32_t*)(PRIVATE_ADDR6) = 13;

  // Fork.
  kpid_t child_pid = proc_fork(&child_func, (void*)0xABCD);
  KEXPECT_GE(child_pid, 0);

  // Update one of the mappings _post-fork_.
  *(uint32_t*)(PRIVATE_ADDR4) = 111;

  // Read a mapping post-fork, _then_ update it.
  KEXPECT_EQ(12, *(uint32_t*)PRIVATE_ADDR5);
  *(uint32_t*)(PRIVATE_ADDR5) = 1212;

  // A third mapping that we update, but the child doesn't read until later.
  *(uint32_t*)(PRIVATE_ADDR6) = 1313;

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
  KEXPECT_EQ(111, *(uint32_t*)PRIVATE_ADDR4);
  KEXPECT_EQ(1212, *(uint32_t*)PRIVATE_ADDR5);
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

typedef struct {
  kpid_t procA3_pid;
  notification_t procA2_ready;
  notification_t procA3_ready;
  notification_t procA2_nop_fork;
  notification_t procA2_nop_fork_done;
  notification_t procA2_exit;
  notification_t procA3_exit;
  notification_t procA3_exited;
  memobj_t* shadow3;
} shadow_test_args;

static void shadow_nop(void* arg) {}

// Helper for the below.
static bc_entry_t* get_bc_entry(kpid_t pid, addr_t address) {
  bc_entry_t* entry = NULL;
  phys_addr_t resolved;
  int result =
      vm_resolve_address_noblock(proc_get(pid), address, /* size= */ 1,
                                 /* is_write= */ false,
                                 /* is_user= */ false, &entry, &resolved);
  KASSERT(result == 0);
  return entry;
}

// Helper to get the memory object from the private mapping.
static memobj_t* get_memobj(kpid_t pid, addr_t address) {
  bc_entry_t* const entry = get_bc_entry(pid, address);
  if (!entry) return NULL;
  memobj_t* obj = entry->obj;
  block_cache_put(entry, BC_FLUSH_NONE);
  return obj;
}

// Helper to get the page address of a page in a particular process.
static phys_addr_t get_proc_page(kpid_t pid, addr_t address) {
  bc_entry_t* const entry = get_bc_entry(pid, address);
  if (!entry) return 0;
  phys_addr_t result = entry->block_phys;
  block_cache_put(entry, BC_FLUSH_NONE);
  return result;
}

// Helpers to get the page address and value of a page in a particular memobj.
static bc_entry_t* get_memobj_entry(memobj_t* obj, size_t addr_offset) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)obj->data;
  void* val;
  if (htbl_get(&data->entries, addr_offset / PAGE_SIZE, &val) != 0) {
    return NULL;  // Entry doesn't exist.
  }
  return (bc_entry_t*)val;
}

static phys_addr_t get_memobj_page(memobj_t* obj, size_t addr_offset) {
  bc_entry_t* entry = get_memobj_entry(obj, addr_offset);
  if (!entry) return 0;
  return entry->block_phys;
}

static uint32_t get_memobj_value(memobj_t* obj, size_t addr_offset) {
  bc_entry_t* entry = get_memobj_entry(obj, addr_offset);
  KASSERT(entry != NULL);
  KASSERT_DBG(addr_offset % sizeof(uint32_t) == 0);
  size_t u32_idx = (addr_offset % PAGE_SIZE) / sizeof(uint32_t);
  return ((uint32_t*)entry->block)[u32_idx];
}

static memobj_t* get_shadow_child(memobj_t* parent) {
  KASSERT(parent->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)parent->data;
  memobj_t* child = data->subobj;
  return child;
}

static void shadow_testA3(void* arg);
static void shadow_testA2(void* arg) {
  shadow_test_args* args = (shadow_test_args*)arg;
  // Get pages into our shadow object (shadow3 in diagram below).
  *(uint32_t*)(PRIVATE_ADDR1) = 3;
  *(uint32_t*)(PRIVATE_ADDR2) = 4;

  args->shadow3 = get_memobj(proc_current()->id, PRIVATE_ADDR1);

  // ...then fork to create procA3.
  args->procA3_pid = proc_fork(&shadow_testA3, arg);
  KEXPECT_GE(args->procA3_pid, 0);

  // Now touch only the first page again.
  *(uint32_t*)(PRIVATE_ADDR1) = 7;
  ntfn_notify(&args->procA2_ready);

  // Wait for procA3 to exit, then wait until we're told to exit.
  int status;
  KEXPECT_EQ(args->procA3_pid, proc_wait(&status));
  KEXPECT_EQ(0, status);
  ntfn_notify(&args->procA3_exited);
  ntfn_await(&args->procA2_nop_fork);
  kpid_t child = proc_fork(&shadow_nop, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
  ntfn_notify(&args->procA2_nop_fork_done);
  ntfn_await(&args->procA2_exit);
}

static void shadow_testA3(void* arg) {
  shadow_test_args* args = (shadow_test_args*)arg;

  // Get pages into our shadow object (shadow5 in diagram below).
  *(uint32_t*)(PRIVATE_ADDR1) = 5;
  *(uint32_t*)(PRIVATE_ADDR2) = 6;

  ntfn_notify(&args->procA3_ready);

  // Shadow tree should now look like the diagram below.  Exit to set off
  // first round of collapse.
  ntfn_await(&args->procA3_exit);
  proc_exit(0);
}

static void shadow_object_collapse_testA(int fd) {
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_PRIVATE, fd, 0, &addr));
  KEXPECT_EQ((void*)PRIVATE_MAP_BASE, addr);
  // Write some values into the mappings, then fork.
  *(uint32_t*)(PRIVATE_ADDR1) = 1;
  *(uint32_t*)(PRIVATE_ADDR2) = 2;

  // What the shadow tree looks like after we fork several times:
  //                     ┌───────┐
  //                     │shadow2│procA1
  //                     │       │
  //                     │page1b │
  //                     │page2b │
  // ┌────┐  ┌───────┐   └───┬───┘
  // │file│◄─┤shadow1│       │         ┌───────┐
  // └────┘  │       │       │         │shadow4│procA2
  //         │page1a │◄──────┤         │       │
  //         │page2a │       │         │page1d │
  //         └───────┘   ┌───┴───┐     │       │
  //                     │shadow3│     └───┬───┘
  //                     │       │         │
  //                     │page1c │◄────────┤
  //                     │page2c │         │
  //                     └───────┘     ┌───┴───┐
  //                                   │shadow5│procA3
  //                                   │       │
  //                                   │page1e │
  //                                   │page2e │
  //                                   └───────┘
  memobj_t* shadow1 = get_memobj(proc_current()->id, PRIVATE_ADDR1);
  KEXPECT_EQ(2, shadow1->num_bc_entries);

  shadow_test_args args;
  ntfn_init(&args.procA2_ready);
  ntfn_init(&args.procA3_ready);
  ntfn_init(&args.procA2_nop_fork);
  ntfn_init(&args.procA2_nop_fork_done);
  ntfn_init(&args.procA2_exit);
  ntfn_init(&args.procA3_exit);
  ntfn_init(&args.procA3_exited);

  kpid_t procA2_pid = proc_fork(&shadow_testA2, &args);
  KEXPECT_GE(procA2_pid, 0);

  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procA2_ready, 5000));
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procA3_ready, 5000));

  // Force new page creation.
  *(uint32_t*)(PRIVATE_ADDR1) = 8;
  *(uint32_t*)(PRIVATE_ADDR2) = 9;

  memobj_t* shadow2 = get_memobj(proc_current()->id, PRIVATE_ADDR1);
  memobj_t* shadow3 = args.shadow3;
  memobj_t* shadow4 = get_memobj(procA2_pid, PRIVATE_ADDR1);
  memobj_t* shadow5 = get_memobj(args.procA3_pid, PRIVATE_ADDR1);

  // Make sure we have the expected structure.
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  KEXPECT_EQ(shadow1, get_shadow_child(shadow2));
  KEXPECT_EQ(shadow1, get_shadow_child(shadow3));
  KEXPECT_EQ(shadow3, get_shadow_child(shadow4));
  KEXPECT_EQ(shadow3, get_shadow_child(shadow5));
  KEXPECT_EQ(2, shadow1->num_bc_entries);
  KEXPECT_EQ(2, shadow2->num_bc_entries);
  KEXPECT_EQ(2, shadow3->num_bc_entries);
  KEXPECT_EQ(1, shadow4->num_bc_entries);
  KEXPECT_EQ(2, shadow5->num_bc_entries);

  const phys_addr_t page1b = get_proc_page(proc_current()->id, PRIVATE_ADDR1);
  const phys_addr_t page2b = get_proc_page(proc_current()->id, PRIVATE_ADDR2);
  KEXPECT_EQ(page1b, get_memobj_page(shadow2, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(page2b, get_memobj_page(shadow2, PRIVATE_ADDR2_OFF));
  const phys_addr_t page2c = get_memobj_page(shadow3, PRIVATE_ADDR2_OFF);
  const phys_addr_t page1d = get_proc_page(procA2_pid, PRIVATE_ADDR1);
  KEXPECT_EQ(0, get_proc_page(procA2_pid, PRIVATE_ADDR2));

  KEXPECT_EQ(1, get_memobj_value(shadow1, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(2, get_memobj_value(shadow1, PRIVATE_ADDR2_OFF));
  KEXPECT_EQ(8, get_memobj_value(shadow2, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(9, get_memobj_value(shadow2, PRIVATE_ADDR2_OFF));
  KEXPECT_EQ(3, get_memobj_value(shadow3, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(4, get_memobj_value(shadow3, PRIVATE_ADDR2_OFF));
  KEXPECT_EQ(7, get_memobj_value(shadow4, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(5, get_memobj_value(shadow5, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(6, get_memobj_value(shadow5, PRIVATE_ADDR2_OFF));

  // Let procA3 exit.
  ntfn_notify(&args.procA3_exit);
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procA3_exited, 5000));

  // We should now have the following structure:
  //                     ┌───────┐
  //                     │shadow2│procA1
  //                     │       │
  //                     │page1b │
  //                     │page2b │
  // ┌────┐  ┌───────┐   └───┬───┘
  // │file│◄─┤shadow1│       │         ┌───────┐
  // └────┘  │       │       │         │shadow4│procA2
  //         │page1a │◄──────┤         │       │
  //         │page2a │       │         │page1d │
  //         └───────┘   ┌───┴───┐     │       │
  //                     │shadow3│     └───┬───┘
  //                     │       │         │
  //                     │page1c │◄────────┘
  //                     │page2c │
  //                     └───────┘
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  KEXPECT_EQ(shadow1, get_shadow_child(shadow2));
  KEXPECT_EQ(shadow1, get_shadow_child(shadow3));
  KEXPECT_EQ(shadow3, get_shadow_child(shadow4));
  // TODO(aoates): consider testing the obj and/or page refcounts as well.

  ntfn_notify(&args.procA2_nop_fork);
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procA2_nop_fork_done, 5000));
  // We should now have the following structure:
  //                     ┌───────┐
  //                     │shadow2│procA1
  //                     │       │
  //                     │page1b │
  //                     │page2b │
  // ┌────┐  ┌───────┐   └───┬───┘
  // │file│◄─┤shadow1│       │         ┌───────┐
  // └────┘  │       │       │         │shadow4│procA2
  //         │page1a │◄──────┤         │       │
  //         │page2a │       │         │page1d │
  //         └───────┘       └─────────┤page2c │
  //                                   └───────┘
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  KEXPECT_EQ(shadow1, get_shadow_child(shadow2));
  KEXPECT_EQ(shadow1, get_shadow_child(shadow4));

  // In the page tables, will be zero (since procA2 forked).
  KEXPECT_EQ(0, get_proc_page(procA2_pid, PRIVATE_ADDR1));
  KEXPECT_EQ(0, get_proc_page(procA2_pid, PRIVATE_ADDR2));

  // ... but the memobj should have the right pages.
  KEXPECT_EQ(page1d, get_memobj_page(shadow4, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(page2c, get_memobj_page(shadow4, PRIVATE_ADDR2_OFF));

  KEXPECT_EQ(8, *(uint32_t*)(PRIVATE_ADDR1));
  KEXPECT_EQ(9, *(uint32_t*)(PRIVATE_ADDR2));

  // Let procA2 exit, which should give us the following structure:
  //         ┌───────┐    ┌───────┐
  //         │shadow1│    │shadow2│procA1
  // ┌────┐  │       │    │       │
  // │file│◄─┤page1a │◄───┤page1b │
  // └────┘  │page2a │    │page2b │
  //         └───────┘    └───────┘

  ntfn_notify(&args.procA2_exit);
  int status;
  KEXPECT_EQ(procA2_pid, proc_waitpid(procA2_pid, &status, 0));
  KEXPECT_EQ(0, status);

  KEXPECT_EQ(shadow1, get_shadow_child(shadow2));
  KEXPECT_EQ(page1b, get_proc_page(proc_current()->id, PRIVATE_ADDR1));
  KEXPECT_EQ(page2b, get_proc_page(proc_current()->id, PRIVATE_ADDR2));

  // Do a no-op fork to force a collapse.
  //           ┌───────┐
  //           │shadow2│procA1
  // ┌────┐    │       │
  // │file│◄───┤page1b │
  // └────┘    │page2b │
  //           └───────┘

  kpid_t child = proc_fork(&shadow_nop, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  // Forking will have reset the page tables --- verify and force back in.
  KEXPECT_EQ(0, get_proc_page(proc_current()->id, PRIVATE_ADDR1));
  KEXPECT_EQ(0, get_proc_page(proc_current()->id, PRIVATE_ADDR2));
  KEXPECT_EQ(8, *(uint32_t*)(PRIVATE_ADDR1));
  KEXPECT_EQ(9, *(uint32_t*)(PRIVATE_ADDR2));

  // Everything should have been collapsed down to shadow2.
  KEXPECT_EQ(shadow2, get_memobj(proc_current()->id, PRIVATE_ADDR1));
  KEXPECT_EQ(2, shadow2->num_bc_entries);
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow2)->type);
  KEXPECT_EQ(page1b, get_proc_page(proc_current()->id, PRIVATE_ADDR1));
  KEXPECT_EQ(page2b, get_proc_page(proc_current()->id, PRIVATE_ADDR2));
  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
}

typedef struct {
  phys_addr_t procB2_addr1;
  phys_addr_t procB2_addr2;
  phys_addr_t procB2_addr3;
  phys_addr_t procB3_addr2;
  kpid_t procB3_pid;
  notification_t procB3_ready;
  notification_t procB3_do_fork;
  notification_t procB3_fork_done;
  notification_t procB3_do_prefork2_check;
  notification_t procB3_prefork2_check_done;
  notification_t procB3_do_fork2;
  notification_t procB3_fork2_done;
  notification_t procB3_exit;
  memobj_t* shadow2;
  memobj_t* shadow3;
} shadow_test_argsB;

static void shadow_testB3(void* arg);

// proc B2 writes a new value to the map, forks, then exits.
static void shadow_testB2(void* arg) {
  shadow_test_argsB* args = (shadow_test_argsB*)arg;
  *(uint32_t*)(PRIVATE_ADDR1) = 101;
  *(uint32_t*)(PRIVATE_ADDR2) = 201;
  *(uint32_t*)(PRIVATE_ADDR3) = 301;
  args->shadow2 = get_memobj(proc_current()->id, PRIVATE_ADDR1);
  args->procB2_addr1 = get_proc_page(proc_current()->id, PRIVATE_ADDR1);
  args->procB2_addr2 = get_proc_page(proc_current()->id, PRIVATE_ADDR2);
  args->procB2_addr3 = get_proc_page(proc_current()->id, PRIVATE_ADDR3);

  // ...then fork to create procB3.
  args->procB3_pid = proc_fork(&shadow_testB3, arg);
  KEXPECT_GE(args->procB3_pid, 0);
}

// proc B3 sets up three scenarios --- one where we're using the shadow page
// from the child shadow obj (with value 101); one where we've overwritten the
// shadow page from the child shadow obj (and it can be discarded); and one
// where we have no version of that shadow page (and it should be migrated to
// us).
static void shadow_testB3(void* arg) {
  shadow_test_argsB* args = (shadow_test_argsB*)arg;
  KEXPECT_EQ(101, *(uint32_t*)PRIVATE_ADDR1);  // Create read-only mapping to
                                               // child subobj's page.
  *(uint32_t*)(PRIVATE_ADDR2) = 202;  // Create overriding mapping.
  // ...and do nothing with PRIVATE_ADDR3
  args->shadow3 = get_memobj(proc_current()->id, PRIVATE_ADDR2);
  args->procB3_addr2 = get_proc_page(proc_current()->id, PRIVATE_ADDR2);

  ntfn_notify(&args->procB3_ready);
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args->procB3_do_fork, 5000));

  // Fork to a no-op to trigger a migration/collapse.
  kpid_t child = proc_fork(&shadow_nop, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
  ntfn_notify(&args->procB3_fork_done);

  // N.B. if we forked again now, everything would collapse because we no longer
  // have the read-only page active for our process (since forking() clears
  // current mappings).  Should we test for that as well, in addition to
  // "overwriting" it below?

  // Wait until the main thread verifies the new structure, then check values.
  // Note that this is somewhat "destructive" as it will cause new page entries
  // to be created, changing the underlying state (but not invalidating the
  // test).
  KEXPECT_EQ(true,
             ntfn_await_with_timeout(&args->procB3_do_prefork2_check, 5000));
  KEXPECT_EQ(101, *(uint32_t*)PRIVATE_ADDR1);
  KEXPECT_EQ(202, *(uint32_t*)PRIVATE_ADDR2);
  KEXPECT_EQ(301, *(uint32_t*)PRIVATE_ADDR3);
  ntfn_notify(&args->procB3_prefork2_check_done);

  KEXPECT_EQ(true, ntfn_await_with_timeout(&args->procB3_do_fork2, 5000));

  // Write to the first address, which should trigger us to create our own copy.
  *(uint32_t*)(PRIVATE_ADDR1) = 102;
  // ...then fork again, which should cause us to fully collapse now.
  child = proc_fork(&shadow_nop, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
  ntfn_notify(&args->procB3_fork2_done);

  // Wait until exit then check the values again for good measure.
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args->procB3_exit, 5000));
  KEXPECT_EQ(102, *(uint32_t*)PRIVATE_ADDR1);
  KEXPECT_EQ(202, *(uint32_t*)PRIVATE_ADDR2);
  KEXPECT_EQ(301, *(uint32_t*)PRIVATE_ADDR3);
}

static void shadow_object_collapse_testB(int fd) {
  KTEST_BEGIN("fork() shadow object collapse test - entry in use");
  void* addr;
  KEXPECT_EQ(0, do_mmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH, PROT_ALL,
                        KMAP_FIXED | KMAP_PRIVATE, fd, 0, &addr));
  KEXPECT_EQ((void*)PRIVATE_MAP_BASE, addr);

  // Write some values into the mappings, then fork.
  *(uint32_t*)(PRIVATE_ADDR1) = 100;
  *(uint32_t*)(PRIVATE_ADDR2) = 200;
  *(uint32_t*)(PRIVATE_ADDR3) = 300;

  // Create a setup where we have a process that is using a page from an
  // intermediate memobj that is otherwise collapsible.
  memobj_t* shadow1 = get_memobj(proc_current()->id, PRIVATE_ADDR1);
  KEXPECT_EQ(3, shadow1->num_bc_entries);

  shadow_test_argsB args;
  ntfn_init(&args.procB3_ready);
  ntfn_init(&args.procB3_do_fork);
  ntfn_init(&args.procB3_fork_done);
  ntfn_init(&args.procB3_do_prefork2_check);
  ntfn_init(&args.procB3_prefork2_check_done);
  ntfn_init(&args.procB3_do_fork2);
  ntfn_init(&args.procB3_fork2_done);
  ntfn_init(&args.procB3_exit);

  kpid_t procB2_pid = proc_fork(&shadow_testB2, &args);
  KEXPECT_GE(procB2_pid, 0);
  int status;
  KEXPECT_EQ(procB2_pid, proc_waitpid(procB2_pid, &status, 0));

  // Verify the structure.
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procB3_ready, 5000));

  // Make sure we have the expected structure.
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  KEXPECT_EQ(shadow1, get_shadow_child(args.shadow2));
  KEXPECT_EQ(args.shadow2, get_shadow_child(args.shadow3));
  KEXPECT_EQ(3, shadow1->num_bc_entries);
  KEXPECT_EQ(3, args.shadow2->num_bc_entries);
  KEXPECT_EQ(1, args.shadow3->num_bc_entries);

  // ADDR1 is from B2's version.  ADDR2 is B3's version.  ADDR3 hasn't been
  // paged in yet (but would be B2's version if it were).
  KEXPECT_EQ(args.shadow2, get_memobj(args.procB3_pid, PRIVATE_ADDR1));
  KEXPECT_EQ(args.shadow3, get_memobj(args.procB3_pid, PRIVATE_ADDR2));
  KEXPECT_EQ(NULL, get_memobj(args.procB3_pid, PRIVATE_ADDR3));

  // Let B3 fork and trigger a collapse.
  ntfn_notify(&args.procB3_do_fork);
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procB3_fork_done, 5000));

  // We should _not_ have fully collapsed, due to the currently-used page in the
  // middle shadow object.  Other pages should have been moved, however.
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  KEXPECT_EQ(shadow1, get_shadow_child(args.shadow2));
  KEXPECT_EQ(args.shadow2, get_shadow_child(args.shadow3));
  KEXPECT_EQ(3, shadow1->num_bc_entries);
  KEXPECT_EQ(2, args.shadow3->num_bc_entries);

  // shadow2 should only have one entry left (the other two migrated).
  KEXPECT_EQ(args.procB2_addr1,
             get_memobj_page(args.shadow2, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(0, get_memobj_page(args.shadow2, PRIVATE_ADDR2_OFF));
  KEXPECT_EQ(0, get_memobj_page(args.shadow2, PRIVATE_ADDR3_OFF));

  // shadow3 should have two entries --- one novel, one migrated.
  KEXPECT_EQ(0,  // No page --- B3 would use shadow2's.
             get_memobj_page(args.shadow3, PRIVATE_ADDR1_OFF));
  KEXPECT_EQ(args.procB3_addr2,  // B3's page (B2/shadow2's discarded).
             get_memobj_page(args.shadow3, PRIVATE_ADDR2_OFF));
  KEXPECT_EQ(args.procB2_addr3,  // shadow's page migrated.
             get_memobj_page(args.shadow3, PRIVATE_ADDR3_OFF));

  // Let B3 page in all values, then we can check them.
  ntfn_notify(&args.procB3_do_prefork2_check);
  KEXPECT_EQ(true,
             ntfn_await_with_timeout(&args.procB3_prefork2_check_done, 5000));

  // ADDR1 is still pointing to the page originally created by B2, which was not
  // migrated to shadow3.  ADDR2 is the version created by B3, and ADDR3 is the
  // version created by B2 that _was_ migrated to shadow3.
  KEXPECT_EQ(args.shadow2, get_memobj(args.procB3_pid, PRIVATE_ADDR1));
  KEXPECT_EQ(args.shadow3, get_memobj(args.procB3_pid, PRIVATE_ADDR2));
  KEXPECT_EQ(args.shadow3, get_memobj(args.procB3_pid, PRIVATE_ADDR3));
  KEXPECT_EQ(args.procB2_addr1, get_proc_page(args.procB3_pid, PRIVATE_ADDR1));
  KEXPECT_NE(args.procB2_addr2, args.procB3_addr2);
  KEXPECT_EQ(args.procB3_addr2, get_proc_page(args.procB3_pid, PRIVATE_ADDR2));
  KEXPECT_EQ(args.procB2_addr3, get_proc_page(args.procB3_pid, PRIVATE_ADDR3));

  // Let B3 fork and trigger a collapse.
  ntfn_notify(&args.procB3_do_fork2);
  KEXPECT_EQ(true, ntfn_await_with_timeout(&args.procB3_fork2_done, 5000));

  // This should have triggered a collapse.
  KEXPECT_EQ(MEMOBJ_VNODE, get_shadow_child(shadow1)->type);
  // TODO(aoates): collapsing should continue and this will need to be updated.
  KEXPECT_EQ(args.shadow2, get_shadow_child(args.shadow3));
  KEXPECT_EQ(3, shadow1->num_bc_entries);
  const uint32_t procB3_guid = proc_get_procguid(args.procB3_pid);
  ntfn_notify(&args.procB3_exit);

  // Let proc B3 finish.
  KEXPECT_EQ(0, proc_wait_guid(args.procB3_pid, procB3_guid, 5000));

  KEXPECT_EQ(0, do_munmap((void*)PRIVATE_MAP_BASE, MAP_LENGTH));
}

// Helpers to reduce typos.
static int so_get_page(memobj_t* obj, int offset, int writable,
                       bc_entry_t** entry_out) {
  return obj->ops->get_page(obj, offset, writable, entry_out);
}

static void so_put_page(bc_entry_t* entry, block_cache_flush_t mode) {
  entry->obj->ops->put_page(entry->obj, entry, mode);
}

static phys_addr_t so_create_page(memobj_t* obj, int offset) {
  bc_entry_t* entry = NULL;
  KEXPECT_EQ(0, so_get_page(obj, offset, /* writable= */ 1, &entry));
  KEXPECT_EQ(obj, entry->obj);
  phys_addr_t result = entry->block_phys;
  so_put_page(entry, BC_FLUSH_NONE);
  return result;
}

// In this one, we just create shadow chains directly without all the forking
// and exiting and such.
static void shadow_object_collapse_testC(memobj_t* file_obj) {
  // Test collapsing an entry up multiple shadow objects.
  KTEST_BEGIN("shadow object collapse: collapse multiple");
  memobj_t* shadow1 = memobj_create_shadow(file_obj);
  memobj_t* shadow2 = memobj_create_shadow(shadow1);
  memobj_t* shadow3 = memobj_create_shadow(shadow2);

  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, so_get_page(shadow1, 0, /* writable= */1, &entry1));
  KEXPECT_EQ(shadow1, entry1->obj);
  void* entry1_block = entry1->block;
  so_put_page(entry1, BC_FLUSH_NONE);

  shadow1->ops->unref(shadow1);
  shadow2->ops->unref(shadow2);
  memobj_t* shadow4 = memobj_create_shadow(shadow3);
  // This should have collapsed shadow1 and shadow2 and migrated the page.
  KEXPECT_EQ(0, so_get_page(shadow4, 0, /* writable= */0, &entry1));
  KEXPECT_EQ(shadow3, entry1->obj);  // Belongs to shadow3.
  KEXPECT_EQ(entry1_block, entry1->block);  // ...but has the same memory.
  so_put_page(entry1, BC_FLUSH_NONE);
  KEXPECT_EQ(file_obj, get_shadow_child(shadow3));
  KEXPECT_EQ(shadow3, get_shadow_child(shadow4));
  shadow3->ops->unref(shadow3);
  shadow4->ops->unref(shadow4);


  KTEST_BEGIN("shadow object collapse: continues past failure");
  // Create the following setup (* means referenced).
  // +---------+------+------+------+------+
  // |   Obj   | off0 | off1 | off2 | off3 |
  // +---------+------+------+------+------+
  // | shadow5 |      |      | C5   |      |
  // | shadow4 |      |      | C4   | D4   |
  // | shadow3 | A3   | B3*  | C3   |      |
  // | shadow2 |      | B2   |      | D2   |
  // | shadow1 | A1   |      |      |      |
  // +---------+------+------+------+------+
  shadow1 = memobj_create_shadow(file_obj);
  shadow2 = memobj_create_shadow(shadow1);
  shadow3 = memobj_create_shadow(shadow2);
  shadow4 = memobj_create_shadow(shadow3);
  memobj_t* shadow5 = memobj_create_shadow(shadow4);

  const phys_addr_t pageA1 = so_create_page(shadow1, 0);
  so_create_page(shadow2, 1);
  const phys_addr_t pageD2 = so_create_page(shadow2, 3);
  const phys_addr_t pageA3 = so_create_page(shadow3, 0);
  KEXPECT_EQ(0, so_get_page(shadow3, 1, /* writable= */1, &entry1));
  const phys_addr_t pageB3 = entry1->block_phys;
  so_create_page(shadow3, 2);
  so_create_page(shadow4, 2);
  const phys_addr_t pageD4 = so_create_page(shadow4, 3);
  const phys_addr_t pageC5 = so_create_page(shadow5, 2);

  shadow1->ops->unref(shadow1);
  shadow2->ops->unref(shadow2);
  shadow3->ops->unref(shadow3);
  shadow4->ops->unref(shadow4);
  memobj_t* shadow6 = memobj_create_shadow(shadow5);  // Trigger collapse.
  // We should now have,
  // +---------+------+------+------+------+
  // |   Obj   | off0 | off1 | off2 | off3 |
  // +---------+------+------+------+------+
  // | shadow5 | A3   |      | C5   | D4   |
  // | shadow3 | A1   | B3*  |      | D2   |
  // +---------+------+------+------+------+

  KEXPECT_EQ(file_obj, get_shadow_child(shadow3));
  KEXPECT_EQ(shadow3, get_shadow_child(shadow5));

  KEXPECT_EQ(pageA1, get_memobj_page(shadow3, 0));
  KEXPECT_EQ(pageB3, get_memobj_page(shadow3, PAGE_SIZE));
  KEXPECT_EQ(0, get_memobj_page(shadow3, 2 * PAGE_SIZE));
  KEXPECT_EQ(pageD2, get_memobj_page(shadow3, 3 * PAGE_SIZE));
  KEXPECT_EQ(pageA3, get_memobj_page(shadow5, 0));
  KEXPECT_EQ(0, get_memobj_page(shadow5, PAGE_SIZE));
  KEXPECT_EQ(pageC5, get_memobj_page(shadow5, 2 * PAGE_SIZE));
  KEXPECT_EQ(pageD4, get_memobj_page(shadow5, 3 * PAGE_SIZE));

  so_put_page(entry1, BC_FLUSH_NONE);

  // Attempt to clear out the cleanup entry list.
  block_cache_free_all(shadow3);  // Technically don't have this ref.

  // Now do one more collapse and verify everything gets into shadow5.
  shadow6->ops->unref(shadow6);
  shadow6 = memobj_create_shadow(shadow5);  // Trigger collapse.
  KEXPECT_EQ(file_obj, get_shadow_child(shadow5));

  KEXPECT_EQ(pageA3, get_memobj_page(shadow5, 0));
  KEXPECT_EQ(pageB3, get_memobj_page(shadow5, PAGE_SIZE));
  KEXPECT_EQ(pageC5, get_memobj_page(shadow5, 2 * PAGE_SIZE));
  KEXPECT_EQ(pageD4, get_memobj_page(shadow5, 3 * PAGE_SIZE));

  shadow5->ops->unref(shadow5);
  shadow6->ops->unref(shadow6);
}

typedef struct {
  memobj_t* obj;
  int result;
  bc_entry_t* entry_out;
  notification_t started;
  notification_t done;
} shadow_testD_args;

static void* shadow_testD_lookup_thread(void* arg) {
  shadow_testD_args* args = (shadow_testD_args*)arg;
  ntfn_notify(&args->started);
  args->result = so_get_page(args->obj, 0, /* writable= */0, &args->entry_out);
  ntfn_notify(&args->done);
  return NULL;
}

static void* shadow_testD_migrate_thread(void* arg) {
  return memobj_create_shadow((memobj_t*)arg);
}

static void shadow_object_collapse_testD(memobj_t* file_obj) {
  // A white-boxy test for a simultaneous get/lookup and migration.  We can't
  // simulaneously have a get() with a migration _from_ the same object (because
  // we wouldn't be migrating if another object had a reference), but we could
  // have one simultaneously with a migration _to_ the same object.
  KTEST_BEGIN("shadow object collapse: simultaneous get and migrate");
  memobj_t* shadow1 = memobj_create_shadow(file_obj);
  memobj_t* shadow2 = memobj_create_shadow(shadow1);

  bc_entry_t* entry1 = NULL;
  KEXPECT_EQ(0, so_get_page(shadow1, 0, /* writable= */1, &entry1));
  KEXPECT_EQ(shadow1, entry1->obj);
  void* entry1_block = entry1->block;
  kstrcpy(entry1->block, "abcd");
  so_put_page(entry1, BC_FLUSH_NONE);
  shadow1->ops->unref(shadow1);

  // Lock shadow2 to prevent the lookup from completing.  This is the white-boxy
  // part.
  shadow_data_t* shadow2_data = (shadow_data_t*)shadow2->data;
  kmutex_lock(&shadow2_data->shadow_lock);

  // Start the lookup in a separate thread, then disable that thread.
  kthread_t lookup_thread;
  shadow_testD_args args;
  args.obj = shadow2;
  ntfn_init(&args.started);
  ntfn_init(&args.done);
  KEXPECT_EQ(0, proc_thread_create(&lookup_thread, &shadow_testD_lookup_thread,
                                   &args));
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.started, 5000));
  KEXPECT_FALSE(ntfn_await_with_timeout(&args.done, 20));
  ksleep(20);  // Make sure the lookup thread is blocked in the lookup.
  kthread_disable(lookup_thread);

  // Note: there are two valid outcomes here --- the migration completes first
  // and the lookup finds the migrated block; OR the lookup/get happens first
  // (creating a reference on the page in shadow1) and the migration does NOT
  // happen.  What should not happen is the migration/collapse happens and the
  // lookup/get gets a new page from the root object.  We only verify the
  // correct scenario that happens in practice today in this test.

  // Start a migration in a second thread (should also block on the mutex).
  kthread_t migrate_thread;
  KEXPECT_EQ(0, proc_thread_create(&migrate_thread,
                                   &shadow_testD_migrate_thread, shadow2));
  // Give the migrate thread time to run and block.
  ksleep(50);

  // Unlock the object, then wait for the migration to complete (it should).
  kmutex_unlock(&shadow2_data->shadow_lock);
  memobj_t* shadow3 = kthread_join(migrate_thread);
  KEXPECT_NE(NULL, shadow3);

  // Let the blocked lookup complete.
  kthread_enable(lookup_thread);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.done, 5000));
  KEXPECT_EQ(NULL, kthread_join(lookup_thread));

  // The lookup result should be consistent with the current post-migration
  // state (this test should hold no matter how the race proceeds).
  bc_entry_t* entry2 = NULL;
  KEXPECT_EQ(0, so_get_page(shadow2, 0, /* writable= */0, &entry2));
  KEXPECT_EQ(0, args.result);
  KEXPECT_EQ(entry2, args.entry_out);
  KEXPECT_EQ(entry1_block, entry2->block);
  KEXPECT_EQ(entry1_block, args.entry_out->block);
  KEXPECT_STREQ("abcd", entry2->block);
  KEXPECT_STREQ("abcd", args.entry_out->block);

  // Further verify that the migration actually happened (per above, only one of
  // the valid outcomes --- may need to be updated in the future).
  KEXPECT_EQ(shadow2, entry2->obj);
  KEXPECT_EQ(shadow2, get_shadow_child(shadow3));
  KEXPECT_EQ(file_obj, get_shadow_child(shadow2));

  so_put_page(entry2, BC_FLUSH_NONE);
  so_put_page(args.entry_out, BC_FLUSH_NONE);
  shadow2->ops->unref(shadow2);
  shadow3->ops->unref(shadow3);
}

static void shadow_object_collapse_test(void) {
  KTEST_BEGIN("fork() shadow object collapse test");
  // Ensure we have a non-shadow object at the base of the chain.
  int fd = vfs_open("_shadow_file", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, MAP_LENGTH));

  memobj_t* file_obj = NULL;
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDWR, &file_obj));

  shadow_object_collapse_testA(fd);
  shadow_object_collapse_testB(fd);
  shadow_object_collapse_testC(file_obj);
  shadow_object_collapse_testD(file_obj);

  file_obj->ops->unref(file_obj);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_shadow_file"));
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
  shadow_object_collapse_test();
}
