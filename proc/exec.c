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

#include <stddef.h>

#include "arch/proc/exec.h"
#include "arch/proc/user_mode.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/kthread-internal.h"
#include "proc/load/load.h"
#include "proc/pmutex.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"

#define KLOG(...) klogfm(KL_PROC, __VA_ARGS__)

int do_execve(const char* path, char* const argv[], char* const envp[],
              void (*cleanup)(const char* path,
                              char* const argv[], char* const envp[],
                              void* arg), void* cleanup_arg) {
  const int fd = vfs_open(path, VFS_O_RDONLY | VFS_O_INTERNAL_EXEC);
  if (fd < 0) {
    KLOG(INFO, "exec error: couldn't open file '%s' for reading: %s\n", path,
         errorname(-fd));
    return fd;
  }

  // Load the binary.
  load_binary_t* binary = NULL;
  int result = load_binary(fd, &binary);
  if (result) {
    KLOG(INFO, "exec error: couldn't load binary from file '%s': %s\n", path,
         errorname(-result));
    return result;
  }

  if (!arch_binary_supported(binary)) {
    return -EINVAL;
  }

  // TODO(aoates): if this (or anything after this) fails, we're hosed.  Should
  // exit the process.

  // Terminate all other threads in the process.
  process_t* const p = proc_current();
  kthread_t thread = kthread_current_thread();
  KASSERT(thread->process == p);
  kspin_lock(&p->spin_mu);
  // Set exiting to prevent new thread creation.
  p->exiting = true;

  FOR_EACH_LIST(iter_link, &p->threads) {
    kthread_data_t* thread_iter =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    if (thread_iter == thread) continue;

    proc_force_signal_on_thread_locked(p, thread_iter, SIGAPOSTKILL);
  }
  // Wait until all other threads actually terminate.
  while (p->threads.head != p->threads.tail) {
    // We don't want scheduler_wait() to re-check signals (which would require
    // re-taking me->process->spin_mu).
    scheduler_wait(&p->thread_change_queue, SWAIT_NO_SIGNAL_CHECK, -1, NULL,
                   &p->spin_mu);
  }
  KASSERT_DBG(list_size(&p->threads) == 1);
  KASSERT_DBG(p->threads.head == &thread->proc_threads_link);

  // Threads can now be created again (in the exec'd process).
  p->exiting = false;
  kspin_unlock(&p->spin_mu);

  // Unmap the current user address space.
  result = do_munmap((void*)MEM_FIRST_MAPPABLE_ADDR,
                     MEM_LAST_USER_MAPPABLE_ADDR -
                     MEM_FIRST_MAPPABLE_ADDR + 1);
  if (result) {
    kfree(binary);
    KLOG(INFO, "exec error: couldn't unmap existing user code: %s\n",
         errorname(-result));
    return result;
  }

  // Map the data into our address space.
  result = load_map_binary(fd, binary);
  if (result) {
    kfree(binary);
    KLOG(INFO, "exec error: couldn't map new user code: %s\n",
         errorname(-result));
    return result;
  }
  vfs_close(fd);

  // Reset any custom signal handlers to the default.
  for (int signo = APOS_SIGMIN; signo <= APOS_SIGMAX; ++signo) {
    ksigaction_t* action = &proc_current()->signal_dispositions[signo];
    if (action->sa_handler != SIG_DFL && action->sa_handler != SIG_IGN) {
      // TODO(aoates): should we reset the flags and mask as well?
      action->sa_handler = SIG_DFL;
    }
  }

  // TODO(aoates): handle set-user-ID/set-group-ID bits.
  kspin_lock(&g_proc_table_lock);
  proc_current()->suid = proc_current()->euid;
  proc_current()->sgid = proc_current()->egid;
  kspin_unlock(&g_proc_table_lock);

  user_context_t ctx;
  result = arch_prep_exec(binary, argv, envp, &ctx);
  if (result) {
    kfree(binary);
    return result;
  }

  pmutex_lock(&p->mu);
  for (int fd = 0; fd < PROC_MAX_FDS; ++fd) {
    if (p->fds[fd].flags & VFS_O_CLOEXEC) {
      if (vfs_close_locked(fd) != 0) {
        KLOG(WARNING, "exec error: unable to close O_CLOEXEC fd %d\n", fd);
      }
    }
  }

  p->user_arch = binary->arch;
  proc_current()->execed = true;
  pmutex_unlock(&p->mu);

  if (cleanup) {
    (*cleanup)(path, argv, envp, cleanup_arg);
  }

  // Jump to the entry point.
  kfree(binary);
  user_context_apply(&ctx);

  // We shouldn't ever get here, since we can't return from user space.
  die("Returned to exec() after jmp into user mode!");
  return 0;
}
