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

static void setup_vnode(vnode_t* vnode, uid_t owner, gid_t group,
                        const char* mode) {
  KASSERT(kstrlen(mode) == 9);
  for (int i = 0; i < 9; ++i) {
    KASSERT(mode[i] == 'r' || mode[i] == 'w' || mode[i] == 'x' ||
            mode[i] == '-');
  }

  vnode->uid = owner;
  vnode->gid = group;
  vnode->mode = 0;
  if (mode[0] == 'r') vnode->mode |= VFS_S_IRUSR;
  if (mode[1] == 'w') vnode->mode |= VFS_S_IWUSR;
  if (mode[2] == 'x') vnode->mode |= VFS_S_IXUSR;
  if (mode[3] == 'r') vnode->mode |= VFS_S_IRGRP;
  if (mode[4] == 'w') vnode->mode |= VFS_S_IWGRP;
  if (mode[5] == 'x') vnode->mode |= VFS_S_IXGRP;
  if (mode[6] == 'r') vnode->mode |= VFS_S_IROTH;
  if (mode[7] == 'w') vnode->mode |= VFS_S_IWOTH;
  if (mode[8] == 'x') vnode->mode |= VFS_S_IXOTH;
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

void vfs_mode_test(void) {
  KTEST_SUITE_BEGIN("vfs mode test");

  check_mode_test();

  // Things to test,
  // * as above, but for a directory
  // * opening a file with appropriate permissions but not on path
  // * opening a file with the requested mode not allowed.
  // * for each syscall, an appropriate representatitive operation
  // * that the superuser can do anything
}
