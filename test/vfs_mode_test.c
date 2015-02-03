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

#include "arch/memory/page_alloc.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs_mode.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static const int kUserA = 1;
static const int kUserB = 2;
static const int kUserC = 3;
static const int kUserD = 3;
static const int kGroupA = 4;
static const int kGroupB = 5;
static const int kGroupC = 6;
static const int kGroupD = 6;

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

// Return the size of the given file.
int get_file_size(const char* path) {
  apos_stat_t stat;
  int result = vfs_stat(path, &stat);
  if (result) return result;
  return stat.st_size;
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
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "-wxrwxrwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "r-xrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserA, kGroupD, "rw-rwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner matches ruid");
  setup_vnode(&vnode, kUserB, kGroupD, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner matches suid");
  setup_vnode(&vnode, kUserC, kGroupD, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner and group match, but "
              "owner doesn't have permissions ");
  setup_vnode(&vnode, kUserA, kGroupA, "---rwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): owner and group match, but "
              "owner and group don't have permissions ");
  setup_vnode(&vnode, kUserA, kGroupA, "------rwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  // Group.
  KTEST_BEGIN("vfs_check_mode(): group matches egid");
  setup_vnode(&vnode, kUserD, kGroupA, "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwx-wxrwx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwxr-xrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupA, "rwxrw-rwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): group matches rgid");
  setup_vnode(&vnode, kUserD, kGroupB, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): group matches sgid");
  setup_vnode(&vnode, kUserD, kGroupC, "rwxrwx---");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  // Other.
  KTEST_BEGIN("vfs_check_mode(): not owner or group");
  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwx-wx");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxr-x");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  setup_vnode(&vnode, kUserD, kGroupD, "rwxrwxrw-");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): root can always read/write/search");
  test_proc.euid = SUPERUSER_UID;
  test_proc.egid = SUPERUSER_GID;
  setup_vnode(&vnode, kUserD, kGroupD, "---------");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_READ, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_WRITE, &test_proc, &vnode));
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_SEARCH, &test_proc, &vnode));

  KTEST_BEGIN("vfs_check_mode(): root can only execute if one exec it is set");
  test_proc.euid = SUPERUSER_UID;
  test_proc.egid = SUPERUSER_GID;
  setup_vnode(&vnode, kUserD, kGroupD, "rw-rw-rw-");
  KEXPECT_EQ(-EACCES, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  setup_vnode(&vnode, kUserD, kGroupD, "--x------");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  setup_vnode(&vnode, kUserD, kGroupD, "-----x---");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
  setup_vnode(&vnode, kUserD, kGroupD, "--------x");
  KEXPECT_EQ(0, vfs_check_mode(VFS_OP_EXEC, &test_proc, &vnode));
}

// Paths for basic read/write/exec tests.
const char k_rwxrwxrwx[] = "mode_test/rwxrwxrwx";
const char k__wxrwxrwx[] = "mode_test/_wxrwxrwx";
const char k_r_xrwxrwx[] = "mode_test/r_xrwxrwx";
const char k_rw_rwxrwx[] = "mode_test/rw_rwxrwx";

const char kDirUnSearchable[] = "mode_test/dir_unsearchable";
const char kFileInUnsearchable[] = "mode_test/dir_unsearchable/file";
const char kDirUnSearchableB[] = "mode_test/dir_unsearchable/dir2";
const char kFileInUnsearchableB[] = "mode_test/dir_unsearchable/dir2/file";
const char kSearchableInUnsearchable[] = "mode_test/dir_unsearchable/dir3";
const char kSearchableInUnsearchableFile[] =
  "mode_test/dir_unsearchable/dir3/file";

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

static void do_cwd_unsearchable_test(void* arg) {
  KTEST_BEGIN("vfs: search bit from cwd");
  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_LE(0, vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH));

  KEXPECT_EQ(0, vfs_mkdir("mode_test/cwd", str_to_mode("rwxrwxrwx")));
  KEXPECT_EQ(0, vfs_chdir("mode_test/cwd"));
  create_file("file", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_mkdir("dir2", str_to_mode("rwxrwxrwx")));
  create_file("dir2/file", "rwxrwxrwx");

  KEXPECT_EQ(0, vfs_chmod(".", str_to_mode("rw-rwxrwx")));

  KEXPECT_EQ(-EACCES, do_open("file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("dir2/file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("./file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("./dir2/file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("../cwd/file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("../cwd/dir2/file", VFS_O_RDONLY));

  // Cleanup.
  kstrcat(orig_cwd, "/mode_test/cwd");
  KEXPECT_EQ(0, vfs_chmod(orig_cwd, str_to_mode("rwxrwxrwx")));
  KEXPECT_EQ(0, vfs_chdir(".."));

  KEXPECT_EQ(0, vfs_unlink("cwd/dir2/file"));
  KEXPECT_EQ(0, vfs_rmdir("cwd/dir2"));
  KEXPECT_EQ(0, vfs_unlink("cwd/file"));
  KEXPECT_EQ(0, vfs_rmdir("cwd"));
}

static void do_basic_rwx_test(void* arg) {
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));
  create_file(k_rwxrwxrwx, "rwxrwxrwx");
  create_file(k__wxrwxrwx, "-wxrwxrwx");
  create_file(k_r_xrwxrwx, "r-xrwxrwx");
  create_file(k_rw_rwxrwx, "rw-rwxrwx");

  KTEST_BEGIN("vfs_open: opening unreadable file for reading");
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDWR));
  KEXPECT_EQ(0,      do_open(k__wxrwxrwx, VFS_O_WRONLY));
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDONLY | VFS_O_INTERNAL_EXEC));
  KEXPECT_EQ(-EACCES, do_open(k__wxrwxrwx, VFS_O_RDWR | VFS_O_INTERNAL_EXEC));

  KTEST_BEGIN("vfs_open: opening unwritable file for writing");
  KEXPECT_EQ(0,      do_open(k_r_xrwxrwx, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_RDWR));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_WRONLY));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_RDWR | VFS_O_INTERNAL_EXEC));
  KEXPECT_EQ(-EACCES, do_open(k_r_xrwxrwx, VFS_O_WRONLY | VFS_O_INTERNAL_EXEC));

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

  KTEST_BEGIN("vfs_open: traversing an unsearchable directory");
  KEXPECT_EQ(0, vfs_mkdir(kDirUnSearchable, str_to_mode("rwxrwxrwx")));
  KEXPECT_EQ(0, vfs_mkdir(kDirUnSearchableB, str_to_mode("rwxrwxrwx")));
  KEXPECT_EQ(0, vfs_mkdir(kSearchableInUnsearchable, str_to_mode("rwxrwxrwx")));
  create_file(kFileInUnsearchable, "rwxrwxrwx");
  create_file(kFileInUnsearchableB, "rwxrwxrwx");
  create_file(kSearchableInUnsearchableFile, "rwxrwxrwx");

  KEXPECT_EQ(0, vfs_chmod(kDirUnSearchableB, str_to_mode("rw-rwxrwx")));
  KEXPECT_EQ(0, vfs_chmod(kDirUnSearchable, str_to_mode("rw-rwxrwx")));

  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchable, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchable, VFS_O_WRONLY));
  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchable, VFS_O_RDWR));
  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchableB, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchableB, VFS_O_WRONLY));
  KEXPECT_EQ(-EACCES, do_open(kFileInUnsearchableB, VFS_O_RDWR));
  KEXPECT_EQ(-EACCES, do_open(kSearchableInUnsearchableFile, VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open(kSearchableInUnsearchableFile, VFS_O_WRONLY));
  KEXPECT_EQ(-EACCES, do_open(kSearchableInUnsearchableFile, VFS_O_RDWR));

  KEXPECT_EQ(0, vfs_chmod(kDirUnSearchable, str_to_mode("rwxrwxrwx")));
  KEXPECT_EQ(0, vfs_chmod(kDirUnSearchableB, str_to_mode("rwxrwxrwx")));

  KTEST_BEGIN("vfs_truncate(): unwritable file");
  create_file("trunc_read",  "r--r--r--");
  create_file("trunc_write", "-w--w--w-");
  create_file("trunc_exec",  "--x--x--x");
  KEXPECT_EQ(-EACCES, vfs_truncate("trunc_read", 123));
  KEXPECT_EQ(0, vfs_truncate("trunc_write", 123));
  KEXPECT_EQ(-EACCES, vfs_truncate("trunc_exec", 123));
  KEXPECT_EQ(0, get_file_size("trunc_read"));
  KEXPECT_EQ(123, get_file_size("trunc_write"));
  KEXPECT_EQ(0, get_file_size("trunc_exec"));
  KEXPECT_EQ(0, vfs_unlink("trunc_read"));
  KEXPECT_EQ(0, vfs_unlink("trunc_write"));
  KEXPECT_EQ(0, vfs_unlink("trunc_exec"));

  // Run tests as an unpriviledged user.
  pid_t child_pid = proc_fork(&do_cwd_unsearchable_test,
                              (void*)kDirUnSearchable);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  // TODO: opening a directory.  opening cwd.  creating a file in an unwritable
  // directory.

  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path(k_rwxrwxrwx));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path(k__wxrwxrwx));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path(k_r_xrwxrwx));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path(k_rw_rwxrwx));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/mode_test/new_file1"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/mode_test/new_file2"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/mode_test/new_file3"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/mode_test"));

  // Cleanup.
  KTEST_BEGIN("vfs mode test: teardown");
  vfs_unlink(kFileInUnsearchable);
  vfs_unlink(kFileInUnsearchableB);
  vfs_unlink(kSearchableInUnsearchableFile);
  KEXPECT_EQ(0, vfs_rmdir(kSearchableInUnsearchable));
  KEXPECT_EQ(0, vfs_rmdir(kDirUnSearchableB));
  KEXPECT_EQ(0, vfs_rmdir(kDirUnSearchable));
  vfs_unlink("mode_test/new_file1");
  vfs_unlink("mode_test/new_file2");
  vfs_unlink("mode_test/new_file3");
  vfs_unlink(k_rwxrwxrwx);
  vfs_unlink(k__wxrwxrwx);
  vfs_unlink(k_r_xrwxrwx);
  vfs_unlink(k_rw_rwxrwx);
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

static void do_root_mode_test(void* arg) {
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  KEXPECT_EQ(-EACCES, do_open("/", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("/root_dir_test", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, do_open("/root_dir_test/file", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, vfs_open("/new_file", VFS_O_RDWR | VFS_O_CREAT, 0));
  KEXPECT_EQ(-EACCES, vfs_open("/root_dir_test/new_file",
                               VFS_O_RDWR | VFS_O_CREAT, 0));
}

// Testing the mode of the root directory.
static void root_mode_test(void) {
  KTEST_BEGIN("vfs mode test: root directory");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("/", &stat));
  const mode_t root_orig_mode = stat.st_mode & ~VFS_S_IFMT;

  KEXPECT_EQ(0, vfs_chmod("/", str_to_mode("rwx------")));
  KEXPECT_EQ(0, vfs_mkdir("/root_dir_test", str_to_mode("rwxrwxrwx")));
  create_file("/root_dir_test/file", "rwxrwxrwx");

  KEXPECT_EQ(0, do_open("/", VFS_O_RDONLY));
  KEXPECT_EQ(0, do_open("/root_dir_test", VFS_O_RDONLY));
  KEXPECT_EQ(0, do_open("/root_dir_test/file", VFS_O_RDONLY));

  // Run tests as an unpriviledged user.
  pid_t child_pid = proc_fork(&do_root_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/root_dir_test"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("/root_dir_test/file"));

  KEXPECT_EQ(0, vfs_unlink("/root_dir_test/file"));
  KEXPECT_EQ(0, vfs_rmdir("/root_dir_test"));
  KEXPECT_EQ(0, vfs_chmod("/", root_orig_mode));
}

static void do_syscall_mode_test(void* arg) {
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  const mode_t kNoRead = VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  const mode_t kNoWrite = VFS_S_IRUSR | VFS_S_IXUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  const mode_t kNoExec = VFS_S_IRUSR | VFS_S_IWUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_read", kNoRead));
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_write", kNoWrite));
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_exec", kNoExec));

  // vfs_open() w/ VFS_O_CREAT
  KTEST_BEGIN("vfs mode test: vfs_open() with VFS_O_CREAT succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_open("syscall_mode_test/no_read/f", VFS_O_CREAT | VFS_O_RDWR, 0));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_read/f"));

  KTEST_BEGIN("vfs mode test: vfs_open() with VFS_O_CREAT fails in non-writable directory");
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/no_write/f", VFS_O_CREAT | VFS_O_RDWR, 0));

  KTEST_BEGIN("vfs mode test: vfs_open() with VFS_O_CREAT fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/no_exec/f", VFS_O_CREAT | VFS_O_RDWR, 0));

  // mkdir()
  KTEST_BEGIN("vfs mode test: vfs_mkdir() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_read/d", 0));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_read/d"));

  KTEST_BEGIN("vfs mode test: vfs_mkdir() fails in non-writable directory");
  KEXPECT_EQ(-EACCES, vfs_mkdir("syscall_mode_test/no_write/d", 0));

  KTEST_BEGIN("vfs mode test: vfs_mkdir() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_mkdir("syscall_mode_test/no_exec/d", 0));

  // mknod()
  KTEST_BEGIN("vfs mode test: vfs_mknod() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_mknod("syscall_mode_test/no_read/chr", VFS_S_IFCHR,
                          makedev(1, 2)));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_read/chr"));

  KTEST_BEGIN("vfs mode test: vfs_mknod() fails in non-writable directory");
  KEXPECT_EQ(-EACCES, vfs_mknod("syscall_mode_test/no_write/chr", VFS_S_IFCHR,
                          makedev(1, 2)));

  KTEST_BEGIN("vfs mode test: vfs_mknod() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_mknod("syscall_mode_test/no_exec/chr", VFS_S_IFCHR,
                          makedev(1, 2)));


  // rmdir()
  KTEST_BEGIN("vfs mode test: vfs_rmdir() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_read/dir", 0));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_read/dir"));

  KTEST_BEGIN("vfs mode test: vfs_rmdir() fails in non-writable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_write/dir", 0));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));
  KEXPECT_EQ(-EACCES, vfs_rmdir("syscall_mode_test/no_write/dir"));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_write/dir"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));

  KTEST_BEGIN("vfs mode test: vfs_rmdir() fails in non-executable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test/no_exec/dir", 0));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));
  KEXPECT_EQ(-EACCES, vfs_rmdir("syscall_mode_test/no_exec/dir"));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_exec/dir"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));


  // unlink()
  KTEST_BEGIN("vfs mode test: vfs_unlink() succeeds in non-readable directory");
  create_file("syscall_mode_test/no_read/f", "---------");
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_read/f"));

  KTEST_BEGIN("vfs mode test: vfs_unlink() fails in non-writable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  create_file("syscall_mode_test/no_write/f", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));
  KEXPECT_EQ(-EACCES, vfs_unlink("syscall_mode_test/no_write/f"));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_write/f"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));

  KTEST_BEGIN("vfs mode test: vfs_unlink() fails in non-executable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  create_file("syscall_mode_test/no_exec/f", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));
  KEXPECT_EQ(-EACCES, vfs_unlink("syscall_mode_test/no_exec/f"));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_exec/f"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));


  // chdir()
  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KTEST_BEGIN("vfs mode test: vfs_chdir() succeeds in non-readable directory");
  KEXPECT_LE(0, vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH));
  KEXPECT_EQ(0, vfs_chdir("syscall_mode_test/no_read"));
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));

  KTEST_BEGIN("vfs mode test: vfs_chdir() succeeds in non-writable directory");
  KEXPECT_EQ(0, vfs_chdir("syscall_mode_test/no_write"));
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));

  KTEST_BEGIN("vfs mode test: vfs_chdir() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_chdir("syscall_mode_test/no_exec"));
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));


  // symlink()
  KTEST_BEGIN("vfs mode test: vfs_symlink() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_symlink("file", "syscall_mode_test/no_read/f"));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_read/f"));

  KTEST_BEGIN("vfs mode test: vfs_symlink() fails in non-writable directory");
  KEXPECT_EQ(-EACCES, vfs_symlink("file", "syscall_mode_test/no_write/f"));

  KTEST_BEGIN("vfs mode test: vfs_symlink() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_symlink("file", "syscall_mode_test/no_exec/f"));


  KTEST_BEGIN("vfs mode test: can't read a no-read directory through a symlink");
  KEXPECT_EQ(0, vfs_symlink("no_read", "syscall_mode_test/link"));
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/link", VFS_O_RDONLY));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/link"));


  KTEST_BEGIN("vfs mode test: can't access a no-execute directory through a symlink");
  KEXPECT_EQ(0, vfs_symlink("no_exec", "syscall_mode_test/link"));
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/link/.", VFS_O_RDONLY));
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/link/./.", VFS_O_RDONLY));
  int fd = vfs_open("syscall_mode_test/link", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/link"));


  KTEST_BEGIN("vfs mode test: can't write to a no-write directory through a symlink");
  KEXPECT_EQ(0, vfs_symlink("no_write", "syscall_mode_test/link"));
  KEXPECT_EQ(-EACCES, vfs_open("syscall_mode_test/link/newfile",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/link"));


  // Setup for metadata syscall tests.
  KTEST_BEGIN("vfs mode test: metadata syscall test setup");
  create_file("syscall_mode_test/no_read/f", "---------");

  KEXPECT_EQ(0,
             vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  create_file("syscall_mode_test/no_write/f", "---------");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  create_file("syscall_mode_test/no_exec/f", "---------");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));


  // lstat()
  apos_stat_t stat;
  KTEST_BEGIN("vfs mode test: vfs_lstat() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_lstat("syscall_mode_test/no_read/f", &stat));

  KTEST_BEGIN("vfs mode test: vfs_lstat() succeeds in non-writable directory");
  KEXPECT_EQ(0, vfs_lstat("syscall_mode_test/no_write/f", &stat));

  KTEST_BEGIN("vfs mode test: vfs_lstat() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_lstat("syscall_mode_test/no_exec/f", &stat));


  // lchown()
  KTEST_BEGIN("vfs mode test: vfs_lchown() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_lchown("syscall_mode_test/no_read/f", -1, -1));

  KTEST_BEGIN("vfs mode test: vfs_lchown() succeeds in non-writable directory");
  KEXPECT_EQ(0, vfs_lchown("syscall_mode_test/no_write/f", -1, -1));

  KTEST_BEGIN("vfs mode test: vfs_lchown() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_lchown("syscall_mode_test/no_exec/f", -1, -1));


  // chmod()
  KTEST_BEGIN("vfs mode test: vfs_chmod() succeeds in non-readable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_read/f", 0));

  KTEST_BEGIN("vfs mode test: vfs_chmod() succeeds in non-writable directory");
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write/f", 0));

  KTEST_BEGIN("vfs mode test: vfs_chmod() fails in non-executable directory");
  KEXPECT_EQ(-EACCES, vfs_chmod("syscall_mode_test/no_exec/f", 0));


  // Teardown for metadata syscall tests.
  KTEST_BEGIN("vfs mode test: metadata syscall test teardown");
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_read/f"));

  KEXPECT_EQ(0,
             vfs_chmod("syscall_mode_test/no_write", kNoWrite | VFS_S_IWUSR));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_write/f"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_write", kNoWrite));

  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec | VFS_S_IXUSR));
  KEXPECT_EQ(0, vfs_unlink("syscall_mode_test/no_exec/f"));
  KEXPECT_EQ(0, vfs_chmod("syscall_mode_test/no_exec", kNoExec));

  // Teardown.
  KTEST_BEGIN("vfs mode test: syscall mode test cleanup");
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("syscall_mode_test/no_read"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("syscall_mode_test/no_write"));
  KEXPECT_EQ(0, vfs_get_vnode_refcount_for_path("syscall_mode_test/no_exec"));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_read"));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_write"));
  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test/no_exec"));
}

// Test that various path-taking syscalls handle modes correctly.
static void syscall_mode_test(void) {
  KTEST_BEGIN("vfs mode test: syscall mode test setup");
  KEXPECT_EQ(0, vfs_mkdir("syscall_mode_test",
                          VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));

  // Run tests as an unpriviledged user.
  pid_t child_pid = proc_fork(&do_syscall_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KEXPECT_EQ(0, vfs_rmdir("syscall_mode_test"));
}

static int creat(const char* path, mode_t mode, uid_t owner, gid_t group) {
  int fd = vfs_open(path, VFS_O_CREAT /* | VFS_O_EXCL */, mode);
  if (fd < 0) return fd;
  fd = vfs_close(fd);
  if (fd) return fd;

  return vfs_chown(path, owner, group);
}

static void access_mode_test_funcA(void) {
  const mode_t kNoRead = VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  const mode_t kNoWrite = VFS_S_IRUSR | VFS_S_IXUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  const mode_t kNoExec = VFS_S_IRUSR | VFS_S_IWUSR | VFS_S_IRWXG | VFS_S_IRWXO;
  KEXPECT_EQ(0, vfs_mkdir("access_mode_test/no_read", kNoRead));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_read", kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_read/no_read", kNoRead, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_read/no_write", kNoWrite, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_read/no_exec", kNoExec, kUserA, kGroupA));

  KEXPECT_EQ(0, vfs_mkdir("access_mode_test/no_write", kNoWrite));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_write", kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_write/no_read", kNoRead, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_write/no_write", kNoWrite, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_write/no_exec", kNoExec, kUserA, kGroupA));

  KEXPECT_EQ(0, vfs_mkdir("access_mode_test/no_exec", kNoExec));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_exec", kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_exec/no_read", kNoRead, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_exec/no_write", kNoWrite, kUserA, kGroupA));
  KEXPECT_EQ(0, creat("access_mode_test/no_exec/no_exec", kNoExec, kUserA, kGroupA));

  KEXPECT_EQ(0, vfs_mkdir("access_mode_test/user_match", VFS_S_IRWXU | VFS_S_IRWXG));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/user_match", kUserA, kGroupC));
  KEXPECT_EQ(0, vfs_mkdir("access_mode_test/group_match", VFS_S_IRWXU | VFS_S_IRWXG));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/group_match", kUserC, kGroupA));

  KEXPECT_EQ(0, vfs_symlink("no_exec", "access_mode_test/no_exec_link"));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_exec_link", kUserA, kGroupA));
  KEXPECT_EQ(0, vfs_symlink("no_exec/no_read", "access_mode_test/no_exec_link2"));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_exec_link2", kUserA, kGroupA));
  KEXPECT_EQ(0, vfs_symlink("no_read", "access_mode_test/no_read_link"));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_read_link", kUserA, kGroupA));
  KEXPECT_EQ(0, vfs_symlink("no_read/no_read", "access_mode_test/no_read_link2"));
  KEXPECT_EQ(0, vfs_chown("access_mode_test/no_read_link2", kUserA, kGroupA));
  KEXPECT_EQ(0, vfs_symlink("bad", "access_mode_test/bad_link"));
  KEXPECT_EQ(0, vfs_lchown("access_mode_test/bad_link", kUserA, kGroupA));

  KEXPECT_EQ(0, setregid(kGroupA, kGroupB));
  KEXPECT_EQ(0, setreuid(kUserA, kUserB));

  KTEST_BEGIN("vfs_access(): F_OK");
  KEXPECT_EQ(0,       vfs_access("access_mode_test", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_exec", F_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_read/a", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_read", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_write", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_exec", F_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_write/a", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_read", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_write", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_exec", F_OK));

  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/a", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_read", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_exec", F_OK));


  KTEST_BEGIN("vfs_access(): R_OK");
  KEXPECT_EQ(0,       vfs_access("access_mode_test", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_exec", R_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_read/a", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read/no_read", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_write", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_exec", R_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_write/a", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_write/no_read", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_write", R_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_exec", R_OK));

  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/a", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_read", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_exec", R_OK));


  KTEST_BEGIN("vfs_access(): W_OK");
  KEXPECT_EQ(0,       vfs_access("access_mode_test", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_write", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_exec", W_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_read/a", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_read", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read/no_write", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_exec", W_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_write/a", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_read", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_write/no_write", W_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_exec", W_OK));

  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/a", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_read", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_exec", W_OK));

  KTEST_BEGIN("vfs_access(): X_OK");
  KEXPECT_EQ(0,       vfs_access("access_mode_test", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec", X_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_read/a", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_read", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read/no_write", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read/no_exec", X_OK));

  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_write/a", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_read", X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write/no_write", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_write/no_exec", X_OK));

  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/a", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_read", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_exec", X_OK));
}

static void access_mode_test_funcB(void) {
  KTEST_BEGIN("vfs_access(): uses real instead of effective uid/gid");
  KEXPECT_EQ(0, setregid(kGroupA, kGroupB));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/user_match", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/user_match", W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/user_match", X_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/group_match", R_OK));

  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserA, kUserB));
  KEXPECT_EQ(0, vfs_access("access_mode_test/user_match", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/group_match", R_OK));

  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/user_match", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/group_match", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/user_match/a", R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/group_match/a", R_OK));

  KEXPECT_EQ(0, setregid(kGroupA, kGroupB));
  KEXPECT_EQ(0, setreuid(kUserA, kUserB));
  KEXPECT_EQ(0, vfs_access("access_mode_test/user_match", R_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/group_match", R_OK));


  KTEST_BEGIN("vfs_access(): combos");
  KEXPECT_EQ(0,       vfs_access("access_mode_test", F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test", R_OK | W_OK | X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test", F_OK | R_OK | W_OK | X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read", F_OK | R_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read", R_OK | W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read", R_OK | W_OK | X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read", W_OK | X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_read", W_OK | X_OK | F_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_write", W_OK | X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_write", R_OK | X_OK));
  KEXPECT_EQ(0,       vfs_access("access_mode_test/no_exec", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec", R_OK | X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", R_OK | W_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec/no_write", R_OK | X_OK));

  KTEST_BEGIN("vfs_access(): bad path elements");
  KEXPECT_EQ(-ENOTDIR, vfs_access("access_mode_test/no_read/no_read/a", X_OK));
  KEXPECT_EQ(-ENOTDIR, vfs_access("access_mode_test/no_read/no_read/a/b", X_OK));
  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/no_read/nope", X_OK));

  KTEST_BEGIN("vfs_access(): invalid mode");
  KEXPECT_EQ(-EINVAL, vfs_access("access_mode_test", 0));
  KEXPECT_EQ(-EINVAL, vfs_access("access_mode_test", -1));
  KEXPECT_EQ(-EINVAL, vfs_access("access_mode_test", 1234));

  KTEST_BEGIN("vfs_access(): through symlink (final element)");
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_exec_link", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec_link", X_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_read_link", X_OK));

  KTEST_BEGIN("vfs_access(): through symlink (final element) B");
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec_link2", F_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec_link2", X_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_read_link", X_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_read_link2", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read_link2", R_OK));

  KTEST_BEGIN("vfs_access(): through symlink (not final element)");
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_exec_link/no_read", F_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_read_link/no_read", X_OK));
  KEXPECT_EQ(-EACCES, vfs_access("access_mode_test/no_read_link/no_read", R_OK));
  KEXPECT_EQ(0, vfs_access("access_mode_test/no_read_link/no_read", W_OK));

  KTEST_BEGIN("vfs_access(): invalid symlink");
  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/bad_link", W_OK));
  KEXPECT_EQ(-ENOENT, vfs_access("access_mode_test/bad_link/x", W_OK));
}

static void access_mode_test_func(void* arg) {
  access_mode_test_funcA();
  access_mode_test_funcB();
}

static void access_mode_test(void) {
  KTEST_BEGIN("vfs mode test: access() mode test setup");
  KEXPECT_EQ(0, vfs_mkdir("access_mode_test",
                          VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));

  // Run tests as an unpriviledged user.
  pid_t child_pid = proc_fork(&access_mode_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  KTEST_BEGIN("vfs_access() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_read/no_read"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_read/no_write"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_read/no_exec"));
  KEXPECT_EQ(0, vfs_rmdir("access_mode_test/no_read"));

  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_write/no_read"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_write/no_write"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_write/no_exec"));
  KEXPECT_EQ(0, vfs_rmdir("access_mode_test/no_write"));

  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_exec/no_read"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_exec/no_write"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_exec/no_exec"));
  KEXPECT_EQ(0, vfs_rmdir("access_mode_test/no_exec"));

  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_exec_link"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_exec_link2"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_read_link"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/no_read_link2"));
  KEXPECT_EQ(0, vfs_unlink("access_mode_test/bad_link"));

  KEXPECT_EQ(0, vfs_rmdir("access_mode_test/user_match"));
  KEXPECT_EQ(0, vfs_rmdir("access_mode_test/group_match"));
  KEXPECT_EQ(0, vfs_rmdir("access_mode_test"));
}

void vfs_mode_test(void) {
  KTEST_SUITE_BEGIN("vfs mode test");
  const int orig_refcount = vfs_get_vnode_refcount_for_path("/");

  const mode_t orig_umask = proc_umask(0);

  check_mode_test();
  basic_rwx_test();
  root_mode_test();
  syscall_mode_test();
  access_mode_test();

  proc_umask(orig_umask);

  KEXPECT_EQ(orig_refcount, vfs_get_vnode_refcount_for_path("/"));

  // Things to test,
  // * as above, but for a directory
  // * opening a file with appropriate permissions but not on path
  // * opening a file with the requested mode not allowed.
  // * for each syscall, an appropriate representatitive operation
  // * that the superuser can do anything
}
