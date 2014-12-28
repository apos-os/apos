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

// A very basic kernel-mode shell.  Currently just for testing ld I/O.
#include "main/kshell.h"

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "arch/common/io.h"
#include "common/config.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"
#include "common/math.h"
#include "dev/ata/ata.h"
#include "memory/block_cache.h"
#include "dev/block_dev.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "dev/timer.h"
#if ENABLE_USB
#include "dev/usb/bus.h"
#include "dev/usb/device.h"
#include "dev/usb/drivers/drivers.h"
#include "dev/usb/hcd.h"
#include "dev/usb/usb.h"
#include "dev/usb/uhci/uhci_cmd.h"
#endif
#include "memory/kmalloc.h"
#include "proc/exec.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/tcgroup.h"
#include "proc/wait.h"
#if ENABLE_TESTS
#include "test/kernel_tests.h"
#include "test/ktest.h"
#endif
#include "user/include/apos/vfs/dirent.h"
#include "vfs/vfs.h"

const char* PATH[] = {
  "/",
  "/bin",
  NULL,
};

#define READ_BUF_SIZE 1024

typedef enum {
  JOB_RUNNING,
  JOB_SUSPENDED,

  // Jobs are never in the following states.
  JOB_CONTINUED,
  JOB_DONE,
  JOB_SIGNALLED,
} job_state_t;

// A background job in the shell.
typedef struct {
  pid_t pid;
  job_state_t state;
  int jobnum;
  char* cmd;
  list_link_t link;
} job_t;

static void print_job_state(const job_t* job, job_state_t state) {
  const char* state_str = "<unknown!>";
  switch (state) {
    case JOB_RUNNING: state_str = "running"; break;
    case JOB_SUSPENDED: state_str = "suspended"; break;
    case JOB_CONTINUED: state_str = "continued"; break;
    case JOB_DONE: state_str = "done"; break;
    // TODO(aoates): print signal description
    case JOB_SIGNALLED: state_str = "signalled"; break;
  }

  ksh_printf("[%d]    %d %-9s  %s\n", job->jobnum, job->pid, state_str,
             job->cmd);
}

// State for the shell.
typedef struct {
  int tty_fd;
  off_t klog_offset;
  list_t jobs;
} kshell_t;

void ksh_printf(const char* fmt, ...) {
  char buf[1024];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buf, fmt, args);
  va_end(args);

  vfs_write(1, buf, kstrlen(buf));
}

#if ENABLE_TESTS

typedef struct {
  const char* name;
  void (*func)(void);
  int run_in_all;
} test_entry_t;

static void run_all_tests(void);

static const test_entry_t TESTS[] = {
  { "ktest", &ktest_test, 0 },

  // Running kmalloc test ruins everything else since it resets malloc state.
  { "kmalloc", &kmalloc_test, 0 },

  { "ld", &ld_test, 1 },
  { "kassert", &kassert_test, 1 },
  { "page_alloc", &page_alloc_test, 1 },
  { "page_alloc_map", &page_alloc_map_test, 1 },
  { "kthread", &kthread_test, 1 },
  { "kthread_pool", &kthread_pool_test, 1 },
  { "interrupt_clobber", &interrupt_clobber_test, 1 },
  { "interrupt_save", &interrupt_save_test, 1 },
  { "kstring", &kstring_test, 1 },
  { "kprintf", &kprintf_test, 1 },
  { "hashtable", &hashtable_test, 1 },
  { "ramdisk", &ramdisk_test, 1 },
  { "slab_alloc", &slab_alloc_test, 1 },
  { "flag_printf", &flag_printf_test, 1 },
  { "ata", &ata_test, 0 },  // Don't run by default so we don't muck up our FS.
  { "ramfs", &ramfs_test, 1 },
  { "vfs_mode", &vfs_mode_test, 1 },
  { "vfs_mount", &vfs_mount_test, 1 },
  { "vfs", &vfs_test, 1 },
  { "hash", &hash_test, 1 },
  { "block_cache", &block_cache_test, 1 },
  { "list", &list_test, 1 },
  { "mmap", &mmap_test, 1 },
  { "vm", &vm_test, 1 },
  { "dmz", &dmz_test, 1 },
  { "proc_load", &proc_load_test, 1 },
  { "fork", &fork_test, 1 },
  { "signal", &signal_test, 1 },
  { "user", &user_test, 1 },
  { "pgroup", &proc_group_test, 1 },
  { "exec", &exec_test, 1 },
  { "cbfs", &cbfs_test, 1 },
  { "ansi_escape", &ansi_escape_test, 1 },
  { "circbuf", &circbuf_test, 1 },
  { "fifo", &fifo_test, 1 },
  { "vfs_fifo", &vfs_fifo_test, 1 },
  { "session", &session_test, 1 },
  { "tty", &tty_test, 1 },
  { "wait", &wait_test, 1 },

  // Fake test for running everything.
  { "all", &run_all_tests, 0 },
  { 0, 0, 0},
};

static void run_all_tests(void) {
  const test_entry_t* e = &TESTS[0];
  while (e->name != 0x0) {
    if (e->run_in_all) {
      e->func();
    }
    e++;
  }
}

typedef struct {
  kshell_t* shell;
  const test_entry_t* entry;
} test_cmd_args_t;

// We run the actual test in another process, since some tests (the VFS tests in
// particular) make assumptions about the file descriptors they can use.
static void do_test_cmd(void* arg) {
  test_cmd_args_t* args = (test_cmd_args_t*)arg;
  vfs_close(0);
  vfs_close(1);
  vfs_close(2);
  vfs_close(args->shell->tty_fd);

  sigset_t mask;
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGINT);
  proc_sigprocmask(SIG_BLOCK, &mask, NULL);

  ktest_begin_all();
  args->entry->func();
  ktest_finish_all();
}

static void test_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("invalid # of args for test: expected 1, got %d\n",
               argc - 1);
    return;
  }

  const test_entry_t* e = &TESTS[0];
  while (e->name != 0x0) {
    if (kstrcmp(argv[1], e->name) == 0) {
      ksh_printf("running test '%s'...\n", argv[1]);
      test_cmd_args_t args = {shell, e};
      proc_fork(&do_test_cmd, &args);
      proc_wait(0);
      return;
    }
    e++;
  }

  ksh_printf("error: unknown test '%s'\n", argv[1]);
}

#endif  // ENABLE_TESTS

static void meminfo_cmd(kshell_t* shell, int argc, char* argv[]) {
  kmalloc_log_state();
}

static void hash_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: hash <number>\n");
    return;
  }
  uint32_t x = atou(argv[1]);
  uint32_t h = fnv_hash(x);
  ksh_printf("%u (0x%x)\n", h, h);
}

// Reads a block from a block device.
static void b_read_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: b_read <dev major> <dev minor> <block>\n");
    return;
  }

  block_dev_t* b = dev_get_block(makedev(atou(argv[1]), atou(argv[2])));
  if (!b) {
    ksh_printf("error: unknown block device %s.%s\n", argv[1], argv[2]);
    return;
  }

  uint32_t block = atou(argv[3]);

  char buf[4096];
  kmemset(buf, 0x0, 4096);
  int error = b->read(b, block, buf, 4096);
  if (error < 0) {
    ksh_printf("error: %s\n", errorname(-error));
    return;
  }

  ksh_printf("read %d bytes:\n", error);
  buf[error] = '\0';
  ksh_printf(buf);
  ksh_printf("\n");
}

// Writes a block to a block device.
static void b_write_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 5) {
    ksh_printf("usage: b_write <dev major> <dev minor> <block> <data>\n");
    return;
  }

  block_dev_t* b = dev_get_block(makedev(atou(argv[1]), atou(argv[2])));
  if (!b) {
    ksh_printf("error: unknown block device %s.%s\n", argv[1], argv[2]);
    return;
  }

  uint32_t block = atou(argv[3]);

  char buf[4096];
  kmemset(buf, 0x0, 4096);
  kstrcpy(buf, argv[4]);
  int error = b->write(b, block, buf, 4096);
  if (error < 0) {
    ksh_printf("error: %s\n", errorname(-error));
    return;
  }

  ksh_printf("wrote %d bytes\n", error);
}

// Simple pager for the kernel log.  With no arguments, prints the next few
// lines of the log (and the current offset).  With one argument, prints the log
// starting at the given offset.
static void klog_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc < 1 || argc > 2) {
    ksh_printf("usage: klog [offset]\n");
    return;
  }

  if (argc == 2) {
    shell->klog_offset = atou(argv[1]);
  }
  char buf[1024];
  int read = klog_read(shell->klog_offset, buf, 1024);

  // Find the last newline, and truncate the last line (if multi-line).
  while (buf[read] != '\n' && read > 0) read--;
  if (read > 0) buf[read] = '\0';

  // Only show up to 20 lines.
  const int MAX_LINES = 20;
  int lines = 0;
  int cline_length = 0;
  for (int i = 0; i < read; ++i) {
    cline_length++;
    if (buf[i] == '\n' || cline_length > 80) {
      lines++;
      cline_length = 0;
    }
    if (lines > MAX_LINES) {
      read = i;
      buf[i] = '\0';
      break;
    }
  }

  ksh_printf("offset: %d\n------", shell->klog_offset);
  ksh_printf(buf);
  ksh_printf("\n------\n");
  shell->klog_offset += read;
}

// Commands for doing {in,out}{b,s,l}.
#define IO_IN_CMD(name, type) \
  static void name##_cmd(kshell_t* shell, int argc, char* argv[]) { \
    if (argc != 2) { \
      ksh_printf("usage: " #name " <port>\n"); \
      return; \
    } \
    ioport_t port = atou(argv[1]); \
    type val = name(port); \
    ksh_printf("0x%x\n", val); \
  }

#define IO_OUT_CMD(name, type) \
  static void name##_cmd(kshell_t* shell, int argc, char* argv[]) { \
    if (argc != 3) { \
      ksh_printf("usage: " #name " <port> <value>\n"); \
      return; \
    } \
    ioport_t port = atou(argv[1]); \
    type value = (type)atou(argv[2]); \
    name(port, value); \
  }

IO_IN_CMD(inb, uint8_t);
IO_IN_CMD(ins, uint16_t);
IO_IN_CMD(inl, uint32_t);

IO_OUT_CMD(outb, uint8_t);
IO_OUT_CMD(outs, uint16_t);
IO_OUT_CMD(outl, uint32_t);

// Registers a timer to print a message at the given interval.
static void timer_cmd_timer_cb(void* arg) {
  ksh_printf((char*)arg);
}
static void timer_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: timer <interval_ms> <limit> <msg>\n");
    return;
  }

  char* buf = (char*)kmalloc(kstrlen(argv[3])+1);
  kstrcpy(buf, argv[3]);
  int result = register_timer_callback(atou(argv[1]), atou(argv[2]),
                                       &timer_cmd_timer_cb, buf);
  if (result < 0) {
    ksh_printf("Could not register timer: %s\n", errorname(-result));
    kfree(buf);
  }
}

// Sleeps the thread for a certain number of ms.
static void sleep_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: sleep <ms>\n");
    return;
  }

  ksleep(atou(argv[1]));
}

static void ls_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc > 3) {
    ksh_printf("usage: ls [-l] [optional path]\n");
    return;
  }
  int long_mode = 0;
  argc--;
  argv++;
  while (argc > 0) {
    if (kstrcmp(argv[0], "-l") == 0) {
      long_mode = 1;
    } else {
      break;
    }
    argc--;
    argv++;
  }
  const char* path = (argc == 0 ? "." : argv[0]);

  int fd = vfs_open(path, VFS_O_RDONLY);
  if (fd < 0) {
    ksh_printf("error: couldn't open directory '%s': %s\n",
               path, errorname(-fd));
    return;
  }

  const int kBufSize = 512;
  char buf[kBufSize];

  while (1) {
    const int len = vfs_getdents(fd, (dirent_t*)(&buf[0]), kBufSize);
    if (len < 0) {
      vfs_close(fd);
      ksh_printf("error: vfs_getdents(): %s\n", errorname(-len));
      return;
    }
    if (len == 0) {
      break;
    }

    int buf_offset = 0;
    do {
      dirent_t* ent = (dirent_t*)(&buf[buf_offset]);
      buf_offset += ent->d_reclen;
      if (long_mode) {
        // TODO(aoates): use fstatat()
        char child_path[1000];
        kstrcpy(child_path, path);
        kstrcat(child_path, "/");
        kstrcat(child_path, ent->d_name);

        apos_stat_t stat;
        const int error = vfs_lstat(child_path, &stat);
        if (error < 0) {
          ksh_printf("<unable to stat %s>\n", ent->d_name);
        } else {
          char mode[11];
          switch (stat.st_mode & VFS_S_IFMT) {
            case VFS_S_IFREG: mode[0] = '-'; break;
            case VFS_S_IFDIR: mode[0] = 'd'; break;
            case VFS_S_IFBLK: mode[0] = 'b'; break;
            case VFS_S_IFCHR: mode[0] = 'c'; break;
            case VFS_S_IFLNK: mode[0] = 'l'; break;
            default: mode[0] = '?'; break;
          }
          mode[1] = stat.st_mode & VFS_S_IRUSR ? 'r' : '-';
          mode[2] = stat.st_mode & VFS_S_IWUSR ? 'w' : '-';
          mode[3] = stat.st_mode & VFS_S_IXUSR ? 'x' : '-';
          mode[4] = stat.st_mode & VFS_S_IRGRP ? 'r' : '-';
          mode[5] = stat.st_mode & VFS_S_IWGRP ? 'w' : '-';
          mode[6] = stat.st_mode & VFS_S_IXGRP ? 'x' : '-';
          mode[7] = stat.st_mode & VFS_S_IROTH ? 'r' : '-';
          mode[8] = stat.st_mode & VFS_S_IWOTH ? 'w' : '-';
          mode[9] = stat.st_mode & VFS_S_IXOTH ? 'x' : '-';
          mode[10] = '\0';

          char link_target[VFS_MAX_PATH_LENGTH + 5];
          kmemset(link_target, 0, VFS_MAX_PATH_LENGTH + 5);
          if ((stat.st_mode & VFS_S_IFMT) == VFS_S_IFLNK) {
            kstrcat(link_target, " -> ");
            int result =
                vfs_readlink(child_path, link_target + 4, VFS_MAX_PATH_LENGTH);
            if (result < 0) {
              ksprintf(link_target + 4, "<unable to readlink: %s>",
                       errorname(-result));
            }
          }

          ksh_printf("%s [%3d] %5d %5d %10d %s%s\n", mode, ent->d_ino,
                     stat.st_uid, stat.st_gid, stat.st_size, ent->d_name,
                     link_target);
        }
      } else {
        ksh_printf("%s\n", ent->d_name);
      }
    } while (buf_offset < len);
  }

  vfs_close(fd);
}

static void mkdir_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: mkdir <path>\n");
    return;
  }
  const int result = vfs_mkdir(argv[1], 0);
  if (result) {
    ksh_printf("error: vfs_mkdir(): %s\n", errorname(-result));
  }
}

static void rmdir_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: rmdir <path>\n");
    return;
  }
  const int result = vfs_rmdir(argv[1]);
  if (result) {
    ksh_printf("error: vfs_rmdir(): %s\n", errorname(-result));
  }
}

static void pwd_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 1) {
    ksh_printf("usage: pwd\n");
    return;
  }
  char buf[VFS_MAX_PATH_LENGTH];
  const int result = vfs_getcwd(buf, VFS_MAX_PATH_LENGTH);
  if (result < 0) {
    ksh_printf("error: vfs_getcwd(): %s\n", errorname(-result));
  } else {
    ksh_printf("%s\n", buf);
  }
}

static void cd_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: cd <path>\n");
    return;
  }
  const int result = vfs_chdir(argv[1]);
  if (result) {
    ksh_printf("error: vfs_chdir(): %s\n", errorname(-result));
  }
}

static void cat_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: cat <path>\n");
    return;
  }

  const int fd = vfs_open(argv[1], VFS_O_RDONLY);
  if (fd < 0) {
    ksh_printf("error: couldn't open %s: %s\n", argv[1], errorname(-fd));
    return;
  }

  const int kBufSize = 512;
  char buf[kBufSize];
  while (1) {
    const int len = vfs_read(fd, buf, kBufSize - 1);
    if (len < 0) {
      ksh_printf("error: couldn't read from file: %s\n", errorname(-len));
      vfs_close(fd);
      return;
    } else if (len == 0) {
      break;
    } else {
      buf[len] = '\0';
      ksh_printf(buf);
    }
  }
  vfs_close(fd);
}

static void write_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: write <path> <data>\n");
    return;
  }

  const int fd = vfs_open(argv[1], VFS_O_RDWR | VFS_O_CREAT, 0);
  if (fd < 0) {
    ksh_printf("error: couldn't open %s: %s\n", argv[1], errorname(-fd));
    return;
  }

  const char* buf = argv[2];
  int buf_len = kstrlen(argv[2]);
  while (buf_len > 0) {
    const int len = vfs_write(fd, buf, buf_len);
    if (len < 0) {
      ksh_printf("error: couldn't write to file: %s\n", errorname(-len));
      vfs_close(fd);
      return;
    } else {
      buf_len -= len;
    }
  }
  vfs_close(fd);
}

static void cp_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: cp <src> <dst>\n");
    return;
  }

  const int src_fd = vfs_open(argv[1], VFS_O_RDONLY);
  if (src_fd < 0) {
    ksh_printf("error: couldn't open %s: %s\n", argv[1], errorname(-src_fd));
    return;
  }

  const int dst_fd = vfs_open(argv[2], VFS_O_WRONLY | VFS_O_CREAT, 0);
  if (dst_fd < 0) {
    ksh_printf("error: couldn't open %s: %s\n", argv[2], errorname(-dst_fd));
    vfs_close(src_fd);
    return;
  }

  const uint32_t time_start = get_time_ms();
  size_t bytes_copied = 0;
  const int kBufSize = 900;
  char buf[kBufSize];
  while (1) {
    const int len = vfs_read(src_fd, buf, kBufSize);
    if (len < 0) {
      ksh_printf("error: couldn't read from file: %s\n", errorname(-len));
      vfs_close(src_fd);
      vfs_close(dst_fd);
      return;
    } else if (len == 0) {
      break;
    } else {
      bytes_copied += len;
      int bytes_to_write = len;
      int offset = 0;
      while (bytes_to_write > 0) {
        const int write_len = vfs_write(dst_fd, buf + offset, bytes_to_write);
        if (write_len < 0) {
          ksh_printf("error: couldn't write to file: %s\n",
                     errorname(-write_len));
          vfs_close(src_fd);
          vfs_close(dst_fd);
          return;
        }
        bytes_to_write -= write_len;
      }
    }
  }
  vfs_close(src_fd);
  vfs_close(dst_fd);
  const uint32_t elapsed = get_time_ms() - time_start;
  ksh_printf("elapsed time: %d ms\n", elapsed);
  ksh_printf("bytes copied: %d\n", bytes_copied);
}

static void rm_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: rm <path>\n");
    return;
  }
  const int result = vfs_unlink(argv[1]);
  if (result) {
    ksh_printf("error: vfs_unlxn(): %s\n", errorname(-result));
  }
}

static void hash_file_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: hash_file <start> <end> <path>\n");
    return;
  }

  const int start = atoi(argv[1]);
  int end = atoi(argv[2]);
  if (end < 0) {
    end = INT_MAX;
  }

  const int fd = vfs_open(argv[3], VFS_O_RDONLY);
  if (fd < 0) {
    ksh_printf("error: couldn't open %s: %s\n", argv[3], errorname(-fd));
    return;
  }

  const uint32_t time_start = get_time_ms();
  const int result = vfs_seek(fd, start, VFS_SEEK_SET);
  if (result < 0) {
    ksh_printf("error: couldn't seek: %s\n", errorname(-result));
    vfs_close(fd);
    return;
  }

  int cpos = start;
  uint32_t h = kFNVOffsetBasis;
  const int kBufSize = 700;
  char buf[kBufSize];
  while (1) {
    if (end >= 0 && cpos >= end) {
      break;
    }
    const int max_len = min(kBufSize, end - cpos);
    const int len = vfs_read(fd, buf, max_len);
    if (len < 0) {
      ksh_printf("error: couldn't read from file: %s\n", errorname(-len));
      vfs_close(fd);
      return;
    } else if (len == 0) {
      break;
    } else {
      cpos += len;
      for (int i = 0; i < len; ++i) {
        h ^= ((uint8_t*)buf)[i];
        h *= kFNVPrime;
      }
    }
  }
  ksh_printf("hash: 0x%x\n", h);
  vfs_close(fd);
  const uint32_t elapsed = get_time_ms() - time_start;
  ksh_printf("elapsed time: %d ms\n", elapsed);
}

void bcstats_cmd(kshell_t* shell, int argc, char** argv) {
  block_cache_log_stats();
}

typedef struct {
  const char* path;
  int argc;
  char** argv;
} boot_child_args_t;

static void boot_child_func(void* arg) {
  setpgid(0, 0);

  boot_child_args_t* args = (boot_child_args_t*)arg;
  char* envp[] = { NULL };
  int result = do_execve(args->path, args->argv, envp, NULL, NULL);
  if (result) {
    klogf("Couldn't boot %s: %s\n", (char*)arg, errorname(-result));
    proc_exit(1);
  }
}

static int get_next_jobnum(const kshell_t* shell) {
  int jobnum = 1;

  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    KASSERT_DBG(job->jobnum >= jobnum);
    if (job->jobnum > jobnum)
      break;
    jobnum++;
  }
  return jobnum;
}

static char* make_job_cmd(int argc, char** argv) {
  size_t strlen = 0;
  for (int i = 0; i < argc; ++i) {
    strlen += kstrlen(argv[i]) + 1;
  }
  char* buf = (char*)kmalloc(strlen);
  char* cbuf = buf;
  for (int i = 0; i < argc; ++i) {
    for (int j = 0; argv[i][j] != '\0'; ++j)
      *(cbuf++) = argv[i][j];
    *(cbuf++) = ' ';
  }
  *(cbuf - 1) = '\0';
  return buf;
}

static void insert_job(job_t* new_job, kshell_t* shell) {
  job_t* prev = NULL;
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    KASSERT_DBG(job->jobnum != new_job->jobnum);
    if (job->jobnum > new_job->jobnum) {
      break;
    }
    prev = job;
  }
  list_insert(&shell->jobs, prev ? &prev->link : NULL, &new_job->link);
}

static job_t* make_job(kshell_t* shell, pid_t pid, int argc, char** argv) {
  job_t* job = (job_t*)kmalloc(sizeof(job_t));
  job->pid = pid;
  job->state = JOB_RUNNING;
  job->jobnum = get_next_jobnum(shell);
  job->cmd = make_job_cmd(argc, argv);
  job->link = LIST_LINK_INIT;
  insert_job(job, shell);
  return job;
}

static job_t* find_job(kshell_t* shell, pid_t pid) {
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    if (job->pid == pid) return job;
  }
  return NULL;
}

static void job_done(kshell_t* shell, job_t* job) {
  list_remove(&shell->jobs, &job->link);
  kfree(job->cmd);
  kfree(job);
}

static pid_t do_wait(kshell_t* shell, pid_t pid, bool block) {
  int options = WUNTRACED;
  if (!block) options |= WNOHANG;

  int status;
  pid_t wait_pid;
  do {
    wait_pid = proc_waitpid(pid, &status, options);
  } while (wait_pid == -EINTR);

  if (wait_pid > 0) {
    job_t* job = find_job(shell, wait_pid);
    KASSERT(job);

    if (WIFEXITED(status)) {
      if (!block) print_job_state(job, JOB_DONE);
      job_done(shell, job);
    } else if (WIFSIGNALED(status)) {
      print_job_state(job, JOB_SIGNALLED);
      job_done(shell, job);
    } else {
      KASSERT_DBG(WIFSTOPPED(status));
      print_job_state(job, JOB_SUSPENDED);
      job->state = JOB_SUSPENDED;
    }
    KASSERT(0 == proc_tcsetpgrp(shell->tty_fd, getpgid(0)));
  }

  return wait_pid;
}

void do_boot_cmd(kshell_t* shell, const char* path, int argc, char** argv) {
  KASSERT(argc >= 1);

  boot_child_args_t args;
  args.path = path;
  args.argc = argc;
  args.argv = argv;

  pid_t child_pid = proc_fork(&boot_child_func, &args);
  if (child_pid < 0) {
    klogf("Unable to fork(): %s\n", errorname(-child_pid));
  } else {
    KASSERT(0 == setpgid(child_pid, child_pid));
    KASSERT(0 == proc_tcsetpgrp(shell->tty_fd, child_pid));

    make_job(shell, child_pid, argc, argv);
    do_wait(shell, child_pid, true);
  }
}

void boot_cmd(kshell_t* shell, int argc, char** argv) {
  if (argc < 2) {
    klogf("Usage: boot <binary> <args...>\n");
    return;
  }
  do_boot_cmd(shell, argv[1], argc - 1, argv + 1);
}

static void fg_bg_cmd(kshell_t* shell, int argc, char** argv, bool is_fg) {
  const char* cmd_name = is_fg ? "fg" : "bg";
  if (argc > 2) {
    ksh_printf("Usage: %s [optional %%jobnum]\n", cmd_name);
    return;
  }
  if (shell->jobs.head == NULL) {
    ksh_printf("%s: no current jobs\n", cmd_name);
    return;
  }

  int jobnum = -1;
  if (argc == 2) {
    if (argv[1][0] == '%') {
      jobnum = atoi(&argv[1][1]);
    }
    if (jobnum <= 0) {
      ksh_printf("invalid job number '%s'\n", argv[1]);
      return;
    }
  }

  job_t* job = NULL;
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* cjob = container_of(link, job_t, link);
    if (jobnum == -1 || cjob->jobnum == jobnum) {
      job = cjob;
      break;
    }
  }

  if (job == NULL) {
    ksh_printf("job %d not found\n", jobnum);
    return;
  }

  // TODO(aoates): move this into main loop
  print_job_state(job, JOB_CONTINUED);
  job->state = JOB_RUNNING;
  if (proc_kill(job->pid, SIGCONT) == 0) {
    if (is_fg) {
      KASSERT(0 == proc_tcsetpgrp(shell->tty_fd, job->pid));
      do_wait(shell, job->pid, true);
    }
  }
}

void fg_cmd(kshell_t* shell, int argc, char** argv) {
  fg_bg_cmd(shell, argc, argv, true);
}

void bg_cmd(kshell_t* shell, int argc, char** argv) {
  fg_bg_cmd(shell, argc, argv, false);
}

void jobs_cmd(kshell_t* shell, int argc, char** argv) {
  if (argc != 1) {
    klogf("Usage: jobs\n");
    return;
  }
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    print_job_state(job, job->state);
  }
}

#if ENABLE_USB

static void uhci_trampoline_cmd(kshell_t* shell, int argc, char* argv[]) {
  uhci_cmd(argc, argv);
}

static const char* lsusb_speed_str(usb_speed_t speed) {
  switch (speed) {
    case USB_LOW_SPEED: return "low";
    case USB_FULL_SPEED: return "full";
  }
  return "<unknown>";
}

static const char* lsusb_state_str(usb_device_state_t state) {
  switch (state) {
    case USB_DEV_INVALID: return "invalid";
    case USB_DEV_ATTACHED: return "attached";
    case USB_DEV_POWERED: return "powered";
    case USB_DEV_DEFAULT: return "default";
    case USB_DEV_ADDRESS: return "address";
    case USB_DEV_CONFIGURED: return "configured";
    case USB_DEV_SUSPENDED: return "suspended";
  }
  return "<unknown>";
}

// Print a USB device and all its children.
const int LSUSB_IDENT = 1;

static void lsusb_print_node(usb_device_t* dev, int indent) {
  char indent_str[100];
  int i;
  for (i = 0; i < indent; ++i) indent_str[i] = ' ';
  indent_str[i] = '\0';

  ksh_printf("%sDevice %d.%d", indent_str, dev->bus->bus_index, dev->address);
  if (dev->port) {
    ksh_printf(" port=%d", dev->port);
  }
  if (dev->state > USB_DEV_INVALID) {
    ksh_printf(" class=0x%d", dev->dev_desc.bDeviceClass);
  }
  ksh_printf(" driver=%s", dev->driver ? dev->driver->name : "<none>");
  ksh_printf(" speed=%s", lsusb_speed_str(dev->speed));
  ksh_printf(" state=%s", lsusb_state_str(dev->state));
  ksh_printf("\n");

  // First print any children.
  if (dev->first_child) {
    lsusb_print_node(dev->first_child, indent + LSUSB_IDENT);
  }

  // ...then siblings.
  if (dev->next) {
    lsusb_print_node(dev->next, indent);
  }
}

static void lsusb_cmd(kshell_t* shell, int argc, char** argv) {
  if (argc != 1) {
    ksh_printf("Usage: lsusb\n");
    return;
  }

  if (usb_num_buses() == 0) {
    ksh_printf("<no USB buses found>\n");
    return;
  }

  for (int bus_idx = 0; bus_idx < usb_num_buses(); bus_idx++) {
    usb_bus_t* bus = usb_get_bus(bus_idx);
    ksh_printf("Bus %d:\n", bus->bus_index);
    lsusb_print_node(bus->root_hub, LSUSB_IDENT);
  }
}
#endif

typedef struct {
  const char* name;
  void (*func)(kshell_t*, int, char*[]);
} cmd_t;

static const cmd_t CMDS[] = {
#if ENABLE_TESTS
  { "test", &test_cmd },
#endif

  { "meminfo", &meminfo_cmd },
  { "hash", &hash_cmd },
  { "b_read", &b_read_cmd },
  { "b_write", &b_write_cmd },
  { "klog", &klog_cmd },

  { "inb", &inb_cmd },
  { "ins", &ins_cmd },
  { "inl", &inl_cmd },
  { "outb", &outb_cmd },
  { "outs", &outs_cmd },
  { "outl", &outl_cmd },

  { "timer", &timer_cmd },
  { "_sleep", &sleep_cmd },

  { "_ls", &ls_cmd },
  { "mkdir", &mkdir_cmd },
  { "rmdir", &rmdir_cmd },
  { "pwd", &pwd_cmd },
  { "cd", &cd_cmd },
  { "_cat", &cat_cmd },
  { "write", &write_cmd },
  { "rm", &rm_cmd },
  { "cp", &cp_cmd },

  { "fg", &fg_cmd },
  { "bg", &bg_cmd },
  { "jobs", &jobs_cmd },

  { "hash_file", &hash_file_cmd },

#if ENABLE_USB
  { "uhci", &uhci_trampoline_cmd },
  { "lsusb", &lsusb_cmd },
#endif

  { "bcstats", &bcstats_cmd },

  { "boot", &boot_cmd },

  { 0x0, 0x0 },
};

static int is_ws(char c) {
  return c == ' ' || c == '\n' || c == '\t';
}

static void parse_and_dispatch(kshell_t* shell, char* cmd) {
  // Parse the command line string.
  int argc = 0;
  char* argv[100];
  int i = 0;
  int in_ws = 1;  // set to 1 to eat leading ws.
  while (cmd[i] != '\0') {
    if (is_ws(cmd[i])) {
      cmd[i] = '\0';
      if (!in_ws) {
        in_ws = 1;
      }
    } else if (in_ws) {
      if (argc >= 100) {
        ksh_printf("error: too many arguments\n");
        return;
      }
      argv[argc] = &cmd[i];
      argc++;
      in_ws = 0;
    }
    i++;
  }

  argv[argc] = 0x0;
  if (argc == 0) {
    return;
  }

  // Find the command.
  const cmd_t* cmd_data = &CMDS[0];
  while (cmd_data->name != 0x0) {
    if (kstrcmp(cmd_data->name, argv[0]) == 0) {
      cmd_data->func(shell, argc, argv);
      return;
    }
    cmd_data++;
  }

  // Search for a binary to run.
  char* path = kmalloc(VFS_MAX_PATH_LENGTH * 2);
  for (int i = 0; PATH[i] != NULL; ++i) {
    ksprintf(path, "%s/%s", PATH[i], argv[0]);
    if (vfs_access(path, X_OK) == 0) {
      do_boot_cmd(shell, path, argc, argv);
      return;
    }
  }
  kfree(path);

  ksh_printf("error: unknown command '%s'\n", argv[0]);
}

void kshell_main(apos_dev_t tty) {
  kshell_t shell = {-1, 0, LIST_INIT};

  proc_setsid();
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", minor(tty));
  shell.tty_fd = vfs_open(tty_name, VFS_O_RDONLY);
  KASSERT(shell.tty_fd == 0);
  shell.tty_fd = vfs_dup2(shell.tty_fd, PROC_MAX_FDS - 1);
  KASSERT(shell.tty_fd == PROC_MAX_FDS - 1);
  vfs_close(0);

  sigset_t mask;
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGTTOU);
  ksigaddset(&mask, SIGTSTP);
  proc_sigprocmask(SIG_BLOCK, &mask, NULL);
  KASSERT(0 == proc_tcsetpgrp(shell.tty_fd, getpgid(0)));

  KASSERT(0 == vfs_open(tty_name, VFS_O_RDONLY));
  KASSERT(1 == vfs_open(tty_name, VFS_O_WRONLY));
  KASSERT(2 == vfs_open(tty_name, VFS_O_WRONLY));

  ksh_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  ksh_printf("@                     APOS                       @\n");
  ksh_printf("@            (c) Andrew Oates 2012               @\n");
  ksh_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

  char read_buf[READ_BUF_SIZE];
  while (1) {
#if ENABLE_TERM_COLOR
    ksh_printf("\x1b[0m");  // Reset before each prompt.
#endif
    ksh_printf("> ");
    int read_len = vfs_read(0, read_buf, READ_BUF_SIZE);
    if (read_len < 0) {
      if (read_len == -EINTR) {
        proc_suppress_signal(proc_current(), SIGINT);
      } else {
        ksh_printf("error: %s\n", errorname(-read_len));
      }
      continue;
    }

    read_buf[read_len] = '\0';
    //klogf("kshell: read %d bytes:\n%s\n", read_len, read_buf);

    parse_and_dispatch(&shell, read_buf);
    //ksprintf(out_buf, "You wrote: '%s'\n", read_buf);
    //ld_write(g_io, out_buf, kstrlen(out_buf));

    do_wait(&shell, -1, false);
  }
}
