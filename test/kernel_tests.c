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

#include "test/kernel_tests.h"

#include "common/arch-config.h"
#include "common/config.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "proc/fork.h"
#include "proc/signal/signal.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

typedef struct {
  const char* name;
  void (*func)(void);
  int run_in_all;
} test_entry_t;

static void run_all_tests(void);
static void do_run_user_tests(void);

static const test_entry_t TESTS[] = {
  { "ktest", &ktest_test, 0 },

  // Running kmalloc test ruins everything else since it resets malloc state.
  { "kmalloc", &kmalloc_test, 0 },

  { "ld", &ld_test, 1 },
  { "kassert", &kassert_test, 1 },
  { "page_alloc", &page_alloc_test, 1 },
  { "kthread", &kthread_test, 1 },
  { "kthread_pool", &kthread_pool_test, 1 },
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
  { "vterm", &vterm_test, 1 },
  { "poll", &poll_test, 1 },
  { "limit", &limit_test, 1 },
  { "socket", &socket_test, 1 },
  { "socket_unix", &socket_unix_test, 1 },
  { "socket_raw", &socket_raw_test, 1 },
  { "socket_udp", &socket_udp_test, 1 },
  { "user_tests", &do_run_user_tests, ARCH_RUN_USER_TESTS },
  { "proc_thread", &proc_thread_test, 1 },
  { "futex", &futex_test, 1 },
  { "dtree", &devicetree_test, 1 },

#if ARCH == ARCH_i586
  { "page_alloc_map", &page_alloc_map_test, 1 },
  { "interrupt_clobber", &interrupt_clobber_test, 1 },
  { "interrupt_save", &interrupt_save_test, 1 },
#endif

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

// File descriptors saved for currently-running tests.  This is not great, but
// the test framework already has plenty of global state.
static int g_stdin_saved = -1;
static int g_stdout_saved = -1;
static int g_stderr_saved = -1;

// Trampoline that reopens std{in,out,err} then runs user tests.
static void do_run_user_tests(void) {
  vfs_close(0);
  vfs_close(1);
  vfs_close(2);

  KASSERT(0 == vfs_dup2(g_stdin_saved, 0));
  KASSERT(1 == vfs_dup2(g_stdout_saved, 1));
  KASSERT(2 == vfs_dup2(g_stderr_saved, 2));

  run_user_tests();
}

typedef struct {
  const test_entry_t* entry;
} test_cmd_args_t;

// We run the actual test in another process, since some tests (the VFS tests in
// particular) make assumptions about the file descriptors they can use.
static void do_test_cmd(void* arg) {
  KASSERT(g_stdin_saved == -1);
  KASSERT(g_stdout_saved == -1);
  KASSERT(g_stderr_saved == -1);
  g_stdin_saved = vfs_dup2(0, 28);
  g_stdout_saved = vfs_dup2(1, 29);
  g_stderr_saved = vfs_dup2(2, 30);
  KASSERT(g_stdin_saved > 0);
  KASSERT(g_stdout_saved > 0);
  KASSERT(g_stderr_saved > 0);

  test_cmd_args_t* args = (test_cmd_args_t*)arg;
  vfs_close(0);
  vfs_close(1);
  vfs_close(2);

  ksigset_t mask;
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGINT);
  proc_sigprocmask(SIG_SETMASK, &mask, NULL);

  struct ksigaction act;
  ksigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = SIG_DFL;
  for (int i = APOS_SIGMIN; i <= APOS_SIGMAX; ++i) {
    proc_sigaction(i, &act, NULL);
  }

  ktest_begin_all();
  args->entry->func();
  ktest_finish_all();
  vfs_close(g_stdin_saved);
  vfs_close(g_stdout_saved);
  vfs_close(g_stderr_saved);
  g_stdin_saved = -1;
  g_stdout_saved = -1;
  g_stderr_saved = -1;
}

int kernel_run_ktest(const char* name) {
  if (!proc_is_superuser(proc_current())) {
    klogf("Cannot run kernel tests as non-superuser\n");
    return -EPERM;
  }

  // Ignore SIGUSR1 to prevent us from being killed by the signal tests.
  struct ksigaction sigaction, old_sigaction;
  ksigemptyset(&sigaction.sa_mask);
  sigaction.sa_flags = 0;
  sigaction.sa_handler = SIG_IGN;
  if (proc_sigaction(SIGUSR1, &sigaction, &old_sigaction)) {
    klogf("Unable to ignore SIGUSR1\n");
    return -1;
  }

  const test_entry_t* e = &TESTS[0];
  int result = -EINVAL;
  while (e->name != 0x0) {
    if (kstrcmp(name, e->name) == 0) {
      klogf("running test '%s'...\n", name);
      test_cmd_args_t args = {e};
      proc_fork(&do_test_cmd, &args);
      proc_wait(0);
      result = 0;
      break;
    }
    e++;
  }

  if (proc_sigaction(SIGUSR1, &old_sigaction, NULL)) {
    klogf("Unable to restore SIGUSR1 action\n");
    return -1;
  }

  if (result) {
    klogf("error: unknown test '%s'\n", name);
  }
  return result;
}
