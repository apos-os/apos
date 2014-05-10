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

#include <stdarg.h>
#include <stdint.h>

#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/page_alloc.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs_mode.h"
#include "vfs/vfs.h"

static const int kUserA = 1;
static const int kUserB = 2;
static const int kUserC = 3;
static const int kUserD = 3;
static const int kGroupA = 4;
static const int kGroupB = 5;
static const int kGroupC = 6;
static const int kGroupD = 6;

mode_t str_to_mode(const char* mode_str) {
  KASSERT(kstrlen(mode_str) == 9);
  for (int i = 0; i < 9; ++i) {
    KASSERT(mode_str[i] == 'r' || mode_str[i] == 'w' || mode_str[i] == 'x' ||
            mode_str[i] == '-');
  }

  mode_t mode = 0;
  if (mode_str[0] == 'r') mode |= VFS_S_IRUSR;
  if (mode_str[1] == 'w') mode |= VFS_S_IWUSR;
  if (mode_str[2] == 'x') mode |= VFS_S_IXUSR;
  if (mode_str[3] == 'r') mode |= VFS_S_IRGRP;
  if (mode_str[4] == 'w') mode |= VFS_S_IWGRP;
  if (mode_str[5] == 'x') mode |= VFS_S_IXGRP;
  if (mode_str[6] == 'r') mode |= VFS_S_IROTH;
  if (mode_str[7] == 'w') mode |= VFS_S_IWOTH;
  if (mode_str[8] == 'x') mode |= VFS_S_IXOTH;

  return mode;
}

static void create_file(const char* path, const char* mode) {
  int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR, str_to_mode(mode));
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
}

// Open the given file and then close it and return 0 if successful.
static int do_open(const char* path, int flags) {
  int fd = vfs_open(path, flags);
  if (fd < 0) return fd;
  vfs_close(fd);
  return 0;
}

// As above, but with with O_CREAT.
static int do_open_create(const char* path, int flags, mode_t mode) {
  KASSERT(flags & VFS_O_CREAT);
  int fd = vfs_open(path, flags, mode);
  if (fd < 0) return fd;
  vfs_close(fd);
  return 0;
}

static void setup_vnode(vnode_t* vnode, uid_t owner, gid_t group,
                        const char* mode) {
  vnode->uid = owner;
  vnode->gid = group;
  vnode->mode = str_to_mode(mode);
}

static void check_mode_test(void) {
  process_t test_proc;
  test_proc.ruid = kUserB;
  test_proc.euid = kUserA;
  test_proc.suid = kUserC;
  test_proc.rgid = kGroupB;
  test_proc.egid = kGroupA;
  test_proc.sgid = kGroupC;

  vnode_t vnode;

  // Owner.
  KTEST_BEGIN("vfs_check_mode(): owner matches euid");
  setup_vnode(&vnode, kUserA, kGroupD, "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "-wxrwxrwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "r-xrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "rw-rwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner matches ruid");
  setup_vnode(&vnode, kUserB, kGroupD, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner matches suid");
  setup_vnode(&vnode, kUserC, kGroupD, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner and group match, but "
              "owner doesn't have permissions ");
  setup_vnode(&vnode, kUserA, kGroupA, "---rwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner and group match, but "
              "owner and group don't have permissions ");
  setup_vnode(&vnode, kUserA, kGroupA, "------rwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  // Group.
  KTEST_BEGIN("vfs_check_mode(): group matches egid");
  setup_vnode(&vnode, kUserD, kGroupA, "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwx-wxrwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwxr-xrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwxrw-rwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): group matches rgid");
  setup_vnode(&vnode, kUserD, kGroupB, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): group matches sgid");
  setup_vnode(&vnode, kUserD, kGroupC, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  // Other.
  KTEST_BEGIN("vfs_check_mode(): not owner or group");
  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwx-wx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxr-x");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxrw-");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): root can do anything");
  test_proc.euid = SUPERUSER_UID;
  test_proc.egid = SUPERUSER_GID;
  setup_vnode(&vnode, kUserD, kGroupD, "---------");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC_OR_SEARCH, &test_proc, &vnode));
}

// Paths for basic read/write/exec tests.
const char k_rwxrwxrwx[] = "mode_test/rwxrwxrwx";
const char k__wxrwxrwx[] = "mode_test/_wxrwxrwx";
const char k_r_xrwxrwx[] = "mode_test/r_xrwxrwx";
const char k_rw_rwxrwx[] = "mode_test/rw_rwxrwx";
const char k_rwx_wxrwx[] = "mode_test/rwx_wxrwx";
const char k_rwxr_xrwx[] = "mode_test/rwxr_xrwx";
const char k_rwxrw_rwx[] = "mode_test/rwxrw_rwx";
const char k_rwxrwx_wx[] = "mode_test/rwxrwx_wx";
const char k_rwxrwxr_x[] = "mode_test/rwxrwxr_x";
const char k_rwxrwxrw_[] = "mode_test/rwxrwxrw_";

// rwxrwxrwx
// _wxrwxrwx
// r_xrwxrwx
// rw_rwxrwx
// rwx_wxrwx
// rwxr_xrwx
// rwxrw_rwx
// rwxrwx_wx
// rwxrwxr_x
// rwxrwxrw_

static void do_basic_rwx_test(void* arg) {
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));
  create_file(k_rwxrwxrwx, "rwxrwxrwx");
  create_file(k__wxrwxrwx, "-wxrwxrwx");
  create_file(k_r_xrwxrwx, "r-xrwxrwx");
  create_file(k_rw_rwxrwx, "rw-rwxrwx");
  create_file(k_rwx_wxrwx, "rwx-wxrwx");
  create_file(k_rwxr_xrwx, "rwxr-xrwx");
  create_file(k_rwxrw_rwx, "rwxrw-rwx");
  create_file(k_rwxrwx_wx, "rwxrwx-wx");
  create_file(k_rwxrwxr_x, "rwxrwxr-x");
  create_file(k_rwxrwxrw_, "rwxrwxrw-");

  KTEST_BEGIN("vfs_open: opening unreadable file for reading");
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDWR));
  KEXPECT_EQ(0,      do_open(k__wxrwxrwx, VFS_O_WRONLY));

  KTEST_BEGIN("vfs_open: opening unwritable file for writing");
  KEXPECT_EQ(0,      do_open(k_r_xrwxrwx, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_RDWR));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_WRONLY));

  KTEST_BEGIN("vfs_open: exec'ing unexecutable file");
  KEXPECT_EQ(-EACCES, do_open(k_rw_rwxrwx, VFS_O_RDONLY | VFS_O_INTERNAL_EXEC));
  KEXPECT_EQ(-EACCES, do_open(k_rw_rwxrwx, VFS_O_RDWR | VFS_O_INTERNAL_EXEC));
  KEXPECT_EQ(-EACCES, do_open(k_rw_rwxrwx, VFS_O_WRONLY | VFS_O_INTERNAL_EXEC));

  KTEST_BEGIN("vfs_open: exec'ing executable file");
  KEXPECT_EQ(0, do_open(k_rwxrwxrwx, VFS_O_RDONLY));
  KEXPECT_EQ(0, do_open(k_rwxrwxrwx, VFS_O_RDWR));
  KEXPECT_EQ(0, do_open(k_rwxrwxrwx, VFS_O_WRONLY));

  KTEST_BEGIN("vfs_open: newly-created file doesn't have mode applied");
  KEXPECT_EQ(0, do_open_create("mode_test/new_file1", VFS_O_RDWR | VFS_O_CREAT,
                               0));
  KEXPECT_EQ(0, do_open_create("mode_test/new_file2", VFS_O_RDONLY | VFS_O_CREAT,
                               0));
  KEXPECT_EQ(0, do_open_create("mode_test/new_file3", VFS_O_WRONLY | VFS_O_CREAT,
                               0));

  // TODO: opening a directory.  opening cwd

  // Cleanup.
  KTEST_BEGIN("vfs mode test: teardown");
  vfs_unlink("mode_test/new_file1");
  vfs_unlink("mode_test/new_file2");
  vfs_unlink("mode_test/new_file3");
  vfs_unlink(k_rwxrwxrwx);
  vfs_unlink(k__wxrwxrwx);
  vfs_unlink(k_r_xrwxrwx);
  vfs_unlink(k_rw_rwxrwx);
  vfs_unlink(k_rwx_wxrwx);
  vfs_unlink(k_rwxr_xrwx);
  vfs_unlink(k_rwxrw_rwx);
  vfs_unlink(k_rwxrwx_wx);
  vfs_unlink(k_rwxrwxr_x);
  vfs_unlink(k_rwxrwxrw_);
}

static void basic_rwx_test(void) {
  KTEST_BEGIN("vfs mode test: setup");
  KEXPECT_EQ(0, vfs_mkdir("mode_test", str_to_mode("rwxrwxrwx")));

  // Run tests as an unpriviledged user.
  pid_t child_pid = proc_fork(&do_basic_rwx_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KEXPECT_EQ(0, vfs_rmdir("mode_test"));
}

void vfs_mode_test(void) {
  KTEST_SUITE_BEGIN("vfs mode test");

  check_mode_test();
  basic_rwx_test();

  // Things to test,
  // * as above, but for a directory
  // * opening a file with appropriate permissions but not on path
  // * opening a file with the requested mode not allowed.
  // * for each syscall, an appropriate representatitive operation
  // * that the superuser can do anything
}
