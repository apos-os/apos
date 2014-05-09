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

// Small wrappers for syscalls.
#ifndef APOO_SYSCALL_WRAPPERS_H
#define APOO_SYSCALL_WRAPPERS_H

#include <stdint.h>

#include "dev/dev.h"
#include "proc/exit.h"
#include "vfs/vfs.h"

static inline int vfs_mknod_wrapper(const char* path, mode_t mode,
                                    int dev_major, int dev_minor) {
  return vfs_mknod(path, mode, mkdev(dev_major, dev_minor));
}

// TODO(aoates): if we have more void syscalls, we should add support directly
// to the syscall templates.
static inline int proc_exit_wrapper(int status) {
  proc_exit(status);
  return 0;  // Should never get here.
}

// Wrapper to manually verify and copy the string tables, and clean up the
// memory before entering the new process.
int execve_wrapper(const char* path_checked,
                   char* const* argv_unchecked,
                   char* const* envp_unchecked);

pid_t getpid_wrapper(void);
pid_t getppid_wrapper(void);

#endif
