// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "common/kprintf.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "proc/fork.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/proc_test_util.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/vfs/dirent.h"
#include "user/include/apos/vfs/stat.h"
#include "vfs/vfs.h"

// ============================================================================
// PART 1: GLOBAL PROCFS TESTS (not tied to specific processes).
// ============================================================================

static void test_procfs_is_mounted(void) {
  KTEST_BEGIN("procfs: verify /proc is mounted");

  apos_stat_t statbuf;
  int result = vfs_stat("/proc", &statbuf);
  KEXPECT_EQ(0, result);
  KEXPECT_TRUE(VFS_S_ISDIR(statbuf.st_mode));
}

static void test_procfs_self_symlink(void) {
  KTEST_BEGIN("procfs: /proc/self symlink points to current process");

  char buf[256];
  kmemset(buf, 0, sizeof(buf));
  int result = vfs_readlink("/proc/self", buf, sizeof(buf) - 1);
  KEXPECT_GT(result, 0);

  kpid_t current_pid = proc_current()->id;
  char expected[32];
  ksprintf(expected, "%d", current_pid);
  KEXPECT_STREQ(expected, buf);
}

static void test_procfs_vnode_file(void) {
  KTEST_BEGIN("procfs: /proc/vnode file exists and is readable");

  int fd = vfs_open("/proc/vnode", VFS_O_RDONLY, 0);
  KEXPECT_GE(fd, 0);

  char* buf = kmalloc(4096);
  int nread = vfs_read(fd, buf, 4095);
  KEXPECT_GT(nread, 0);

  kfree(buf);
  vfs_close(fd);
}

static void test_procfs_root_entries(void) {
  KTEST_BEGIN("procfs: /proc contains expected static entries");

  // We should see 'self', 'vnode', process 0, process 1, and current process.
  // All other entries should be all-digit PIDs.
  int fd = vfs_open("/proc", VFS_O_RDONLY, 0);
  KEXPECT_GE(fd, 0);

  char* buf = kmalloc(8192);
  int nread = vfs_getdents(fd, (struct kdirent*)buf, 8192);
  KEXPECT_GT(nread, 0);

  // Track what we've found.
  bool found_self = false;
  bool found_vnode = false;
  bool found_proc0 = false;
  bool found_proc1 = false;
  bool found_current = false;

  kpid_t current_pid = proc_current()->id;
  char current_pid_str[32];
  ksprintf(current_pid_str, "%d", current_pid);

  struct kdirent* entry = (struct kdirent*)buf;
  while ((char*)entry < buf + nread) {
    const char* name = entry->d_name;

    // Check for known static entries.
    if (kstrcmp(name, "self") == 0) {
      found_self = true;
    } else if (kstrcmp(name, "vnode") == 0) {
      found_vnode = true;
    } else if (kstrcmp(name, "0") == 0) {
      found_proc0 = true;
    } else if (kstrcmp(name, "1") == 0) {
      found_proc1 = true;
    } else if (kstrcmp(name, current_pid_str) == 0) {
      found_current = true;
    } else if (kstrcmp(name, ".") == 0 || kstrcmp(name, "..") == 0) {
      // Skip . and .. directory entries.
    } else {
      // All other entries should be all digits (PIDs).
      bool all_digits = true;
      for (int i = 0; name[i] != '\0'; i++) {
        if (!kisdigit(name[i])) {
          all_digits = false;
          break;
        }
      }
      KEXPECT_TRUE(all_digits);
    }

    entry = (struct kdirent*)((char*)entry + entry->d_reclen);
  }

  // Verify we found all expected entries.
  KEXPECT_TRUE(found_self);
  KEXPECT_TRUE(found_vnode);
  KEXPECT_TRUE(found_proc0);
  KEXPECT_TRUE(found_proc1);
  KEXPECT_TRUE(found_current);

  kfree(buf);
  vfs_close(fd);
}

static void test_procfs_nonexistent_process(void) {
  KTEST_BEGIN("procfs: accessing nonexistent process returns ENOENT");

  KEXPECT_EQ(-ENOENT, vfs_open("/proc/9999", VFS_O_RDONLY | VFS_O_DIRECTORY, 0));
  KEXPECT_EQ(-ENOENT, vfs_open("/proc/9999/status", VFS_O_RDONLY, 0));
}

// ============================================================================
// PART 2: PER-PROCESS TEST FRAMEWORK.
// ============================================================================

// Expected state of a process in procfs.
typedef struct {
  kpid_t pid;
  kpid_t ppid;  // -1 means no parent (root process).
  const char* state;  // e.g., "RUNNING", "ZOMBIE".
  const char* cwd;  // Expected current working directory (or NULL if error expected).

  // Status file - exact expected contents (multiline string).
  const char* status_contents;

  // VM file validation.
  bool check_vm_empty;  // If true, expect vm to be empty.

  // CWD validation: if 0, expect readlink to succeed and match cwd field.
  // Otherwise, expect readlink to return this error code (e.g., -EIO for zombies).
  int expected_cwd_error;
} procfs_expected_state_t;

// Helper to read a file from /proc/<pid>/<filename> into the given buffer.
// Returns the number of bytes read on success, or a negative error code.
static int read_proc_file(kpid_t pid, const char* filename, char* buf, int buflen) {
  char path[64];
  ksnprintf(path, sizeof(path), "/proc/%d/%s", pid, filename);

  int fd = vfs_open(path, VFS_O_RDONLY, 0);
  if (fd < 0) return fd;

  int nread = vfs_read(fd, buf, buflen - 1);
  buf[nread] = '\0';
  vfs_close(fd);
  return nread;
}

// Helper to verify /proc/<pid> directory contains expected entries.
static void verify_proc_dir_entries(kpid_t pid) {
  char proc_dir[64];
  ksprintf(proc_dir, "/proc/%d", pid);

  edirent_t expected[] = {
    { -1, "." },
    { -1, ".." },
    { -1, "cwd" },
    { -1, "status" },
    { -1, "vm" },
  };

  KEXPECT_EQ(0, compare_dirents_p(proc_dir, 5, expected));
}

// Helper to verify CWD symlink.
// If expected_cwd_error is 0, expect success and match expected_cwd.
// Otherwise, expect readlink to return expected_cwd_error.
static void verify_cwd_symlink(kpid_t pid, const char* expected_cwd,
                               int expected_cwd_error) {
  char cwd_path[64];
  ksprintf(cwd_path, "/proc/%d/cwd", pid);

  char* buf = kmalloc(VFS_MAX_PATH_LENGTH);
  kmemset(buf, 0, VFS_MAX_PATH_LENGTH);
  int result = vfs_readlink(cwd_path, buf, VFS_MAX_PATH_LENGTH - 1);

  if (expected_cwd_error == 0) {
    // Expect success.
    KEXPECT_GT(result, 0);
    if (expected_cwd) {
      KEXPECT_STREQ(expected_cwd, buf);
    }
  } else {
    // Expect error.
    KEXPECT_EQ(expected_cwd_error, result);
  }

  kfree(buf);
}

// Main helper function to verify all procfs entries for a process.
static void verify_procfs_state(const procfs_expected_state_t* expected) {
  // Test 1: Verify /proc/<pid> directory entries.
  verify_proc_dir_entries(expected->pid);

  char* buf = kmalloc(4096);

  // Test 2: Verify status file contents.
  if (expected->status_contents) {
    int result = read_proc_file(expected->pid, "status", buf, 4096);
    KEXPECT_GT(result, 0);
    KEXPECT_MULTILINE_STREQ(expected->status_contents, buf);
  }

  // Test 3: Verify VM file.
  int result = read_proc_file(expected->pid, "vm", buf, 4096);
  KEXPECT_GE(result, 0);

  if (expected->check_vm_empty) {
    KEXPECT_STREQ("", buf);
  } else {
    const char* kExpectedVmEntry =
#if ARCH == ARCH_i586
        "< start: 0xd0000000  end: 0xe0000000  memobj: 0x0 >";
#elif ARCH == ARCH_x86_64
        "< start: 0xffffffffd0000000  end: 0xffffffffe0000000  memobj: 0x0 >";
#elif ARCH == ARCH_riscv64
        "< start: 0xffffffff80000000  end: 0xffffffffc0000000  memobj: 0x0 >";
#else
        "";
#error Bad architecture
#endif
    KEXPECT_NE((const char*)NULL, kstrstr(buf, kExpectedVmEntry));
  }
  kfree(buf);

  // Test 4: Verify CWD symlink (always check, even for zombies).
  verify_cwd_symlink(expected->pid, expected->cwd, expected->expected_cwd_error);
}

// ============================================================================
// PART 3: TOP-LEVEL PER-PROCESS TESTS.
// ============================================================================

// Child process for normal process test.
typedef struct {
  notification_t ready;
  notification_t can_exit;
} normal_child_args_t;

static void normal_child_func(void* arg) {
  normal_child_args_t* args = (normal_child_args_t*)arg;
  KEXPECT_EQ(0, vfs_chdir("/_procfs_test_cwd/x"));
  ntfn_notify(&args->ready);
  ntfn_await(&args->can_exit);
}

static void test_procfs_normal_process(void) {
  KTEST_BEGIN("procfs: normal running process");

  normal_child_args_t args;
  ntfn_init(&args.ready);
  ntfn_init(&args.can_exit);

  KEXPECT_EQ(0, vfs_mkdir("/_procfs_test_cwd", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("/_procfs_test_cwd/x", VFS_S_IRWXU));

  kpid_t child_pid = proc_fork(&normal_child_func, &args);
  KEXPECT_GT(child_pid, 0);

  // Wait for child to be ready.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args.ready, 1000));

  // Get parent PID for comparison.
  kpid_t parent_pid = proc_current()->id;

  // Get the child's process group.
  process_t* child_proc = proc_get_ref(child_pid);
  kspin_lock(&g_proc_table_lock);
  kpid_t child_pgroup = child_proc->pgroup;
  kspin_unlock(&g_proc_table_lock);
  proc_put(child_proc);

  // Build expected status contents.
  char* expected_status = kmalloc(2048);
  ksprintf(expected_status,
           "pid: %d\n"
           "state: RUNNING\n"
           "ppid: %d\n"
           "cwd: /_procfs_test_cwd/x\n"
           "ruid/rgid:     0     0\n"
           "euid/egid:     0     0\n"
           "suid/sgid:     0     0\n"
           "pgroup: %d\n"
           "exec'ed: 0\n"
           "user_arch: 0\n"
           "children:\n",
           child_pid, parent_pid, child_pgroup);

  procfs_expected_state_t expected = {
    .pid = child_pid,
    .ppid = parent_pid,
    .state = "RUNNING",
    .cwd = "/_procfs_test_cwd/x",
    .status_contents = expected_status,
    .check_vm_empty = false,
    .expected_cwd_error = 0,  // 0 means expect success and match cwd field.
  };

  verify_procfs_state(&expected);

  kfree(expected_status);

  // Open some fds to test after the child exits.
  char path[100];
  ksprintf(path, "/proc/%d", child_pid);
  int dir_fd = vfs_open(path, VFS_O_RDONLY | VFS_O_DIRECTORY);
  KEXPECT_GE(dir_fd, 0);
  ksprintf(path, "/proc/%d/status", child_pid);
  int status_fd = vfs_open(path, VFS_O_RDONLY);
  KEXPECT_GE(status_fd, 0);
  ksprintf(path, "/proc/%d/vm", child_pid);
  int vm_fd = vfs_open(path, VFS_O_RDONLY);
  KEXPECT_GE(vm_fd, 0);

  // Let child exit.
  ntfn_notify(&args.can_exit);

  int status;
  KEXPECT_EQ(child_pid, proc_waitpid(child_pid, &status, 0));

  // Make sure we get errors (not crashes or data) when we read from the
  // still-open file descriptors.
  KEXPECT_EQ(-EIO, vfs_read(status_fd, path, 100));
  KEXPECT_EQ(-EIO, vfs_read(vm_fd, path, 100));
  // getdents doesn't actually look at the process, so it will succeed.
  kdirent_t dirent;
  KEXPECT_EQ(0, vfs_getdents(dir_fd, &dirent, sizeof(dirent)));

  // TODO(aoates): write a test that verifies a race on cwd.

  KEXPECT_EQ(0, vfs_close(dir_fd));
  KEXPECT_EQ(0, vfs_close(status_fd));
  KEXPECT_EQ(0, vfs_close(vm_fd));
  KEXPECT_EQ(0, vfs_rmdir("/_procfs_test_cwd/x"));
  KEXPECT_EQ(0, vfs_rmdir("/_procfs_test_cwd"));
}

static void test_procfs_zombie_process(void) {
  KTEST_BEGIN("procfs: zombie process");

  ptu_zombie_t* zombie = ptu_zombie_create(false, NULL, NULL);
  kpid_t zombie_pid = zombie->zombie;
  kpid_t parent_pid = zombie->parent_pid;

  KEXPECT_EQ(PROC_ZOMBIE, proc_state(zombie_pid));

  // Get the zombie's process group.
  process_t* zombie_proc = proc_get_ref(zombie_pid);
  kspin_lock(&g_proc_table_lock);
  kpid_t zombie_pgroup = zombie_proc->pgroup;
  kspin_unlock(&g_proc_table_lock);
  proc_put(zombie_proc);

  // Build expected status contents for zombie.
  // Note: cwd for zombie is <none> since it's been cleaned up.
  char* expected_status = kmalloc(2048);
  ksprintf(expected_status,
           "pid: %d\n"
           "state: ZOMBIE\n"
           "ppid: %d\n"
           "cwd: <none>\n"
           "ruid/rgid:     0     0\n"
           "euid/egid:     0     0\n"
           "suid/sgid:     0     0\n"
           "pgroup: %d\n"
           "exec'ed: 0\n"
           "user_arch: 0\n"
           "children:\n",
           zombie_pid, parent_pid, zombie_pgroup);

  procfs_expected_state_t expected = {
    .pid = zombie_pid,
    .ppid = parent_pid,
    .state = "ZOMBIE",
    .status_contents = expected_status,
    .check_vm_empty = false,
    .expected_cwd_error = -EIO,  // Zombies have NULL cwd, readlink returns -EIO.
  };

  verify_procfs_state(&expected);

  kfree(expected_status);
  ptu_zombie_cleanup(zombie);
}

static void test_procfs_uber_zombie_process(void) {
  KTEST_BEGIN("procfs: uber-zombie process");

  ptu_zombie_t* zombie = ptu_zombie_create(true, NULL, NULL);
  kpid_t zombie_pid = zombie->zombie;
  kpid_t parent_pid = zombie->parent_pid;

  KEXPECT_EQ(PROC_ZOMBIE, proc_state(zombie_pid));

  // Get the zombie's process group.
  process_t* zombie_proc = proc_get_ref(zombie_pid);
  kspin_lock(&g_proc_table_lock);
  kpid_t zombie_pgroup = zombie_proc->pgroup;
  kspin_unlock(&g_proc_table_lock);
  proc_put(zombie_proc);

  // Build expected status contents for uber-zombie.
  char* expected_status = kmalloc(2048);
  ksprintf(expected_status,
           "pid: %d\n"
           "state: ZOMBIE\n"
           "ppid: %d\n"
           "cwd: <none>\n"
           "ruid/rgid:     0     0\n"
           "euid/egid:     0     0\n"
           "suid/sgid:     0     0\n"
           "pgroup: %d\n"
           "exec'ed: 0\n"
           "user_arch: 0\n"
           "children:\n",
           zombie_pid, parent_pid, zombie_pgroup);

  procfs_expected_state_t expected = {
    .pid = zombie_pid,
    .ppid = parent_pid,
    .state = "ZOMBIE",
    .status_contents = expected_status,
    .check_vm_empty = false,
    .expected_cwd_error = -EIO,  // Uber-zombies have NULL cwd, readlink returns -EIO.
  };

  verify_procfs_state(&expected);

  kfree(expected_status);
  ptu_zombie_cleanup(zombie);
}

static void test_procfs_root_process(void) {
  KTEST_BEGIN("procfs: root process (PID 0, no parent)");

  kpid_t root_pid = 0;

  // Verify root process directory exists and has expected entries.
  verify_proc_dir_entries(root_pid);

  // Read status file - we can't predict exact contents because
  // root process children are dynamic, but we can verify basic fields.
  char* buf = kmalloc(4096);

  int nread = read_proc_file(root_pid, "status", buf, 4096);
  KEXPECT_GT(nread, 0);

  // Verify basic fields are present.
  KEXPECT_NE((const char*)NULL, kstrstr(buf, "pid: 0"));
  KEXPECT_NE((const char*)NULL, kstrstr(buf, "ppid: -1"));  // No parent.
  KEXPECT_NE((const char*)NULL, kstrstr(buf, "state: RUNNING"));
  KEXPECT_NE((const char*)NULL, kstrstr(buf, "children:\n      1 (RUNNING)"));

  // Verify VM file is readable.
  int vm_nread = read_proc_file(root_pid, "vm", buf, 4096);
  KEXPECT_GE(vm_nread, 0);

  kfree(buf);

  // Verify CWD is readable (root should have a valid cwd).
  char cwd_path[64];
  ksprintf(cwd_path, "/proc/%d/cwd", root_pid);

  char* cwd_buf = kmalloc(VFS_MAX_PATH_LENGTH);
  int cwd_result = vfs_readlink(cwd_path, cwd_buf, VFS_MAX_PATH_LENGTH - 1);
  KEXPECT_GT(cwd_result, 0);

  kfree(cwd_buf);
}

void procfs_test(void) {
  KTEST_SUITE_BEGIN("procfs");
  // Part 1: Global procfs tests.
  test_procfs_is_mounted();
  test_procfs_self_symlink();
  test_procfs_vnode_file();
  test_procfs_root_entries();
  test_procfs_nonexistent_process();

  // Part 2: Per-process tests.
  test_procfs_normal_process();
  test_procfs_zombie_process();
  test_procfs_uber_zombie_process();
  test_procfs_root_process();
}
