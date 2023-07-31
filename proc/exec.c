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
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/load/load.h"
#include "vfs/vfs.h"

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

  // Unmap the current user address space.
  // TODO(aoates): if this (or anything after this) fails, we're hosed.  Should
  // exit the process.
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
  proc_current()->suid = proc_current()->euid;
  proc_current()->sgid = proc_current()->egid;

  user_context_t ctx;
  result = arch_prep_exec(binary, argv, envp, &ctx);
  if (result) {
    kfree(binary);
    return result;
  }

  proc_current()->user_arch = binary->arch;
  if (cleanup) {
    (*cleanup)(path, argv, envp, cleanup_arg);
  }

  // Jump to the entry point.
  kfree(binary);
  proc_current()->execed = true;
  user_context_apply(&ctx);

  // We shouldn't ever get here, since we can't return from user space.
  die("Returned to exec() after jmp into user mode!");
  return 0;
}
