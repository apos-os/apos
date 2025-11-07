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
#include "vfs/fcntl.h"

#include "common/errno.h"
#include "proc/pmutex.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/file.h"
#include "vfs/vfs_internal.h"

#define SETFD_VALID_FLAGS VFS_O_CLOEXEC

static int fcntl_dupfd(process_t* proc, file_t* file, int orig_fd, int cmd,
                       int arg) REQUIRES(proc->mu) {
  int new_fd = vfs_next_free_fd(proc, arg);
  if (new_fd < 0) {
    return new_fd;
  }

  KASSERT_DBG(proc->fds[new_fd].file == PROC_UNUSED_FD);
  file_ref(file);
  proc->fds[new_fd] = proc->fds[orig_fd];
  // TODO(aoates): clear O_CLOEXEC.
  return new_fd;
}

static int fcntl_getfd(process_t* proc, file_t* file, int orig_fd, int cmd,
                       int arg) REQUIRES(proc->mu) {
  return proc->fds[orig_fd].flags;
}

static int fcntl_setfd(process_t* proc, file_t* file, int orig_fd, int cmd,
                       int arg) REQUIRES(proc->mu) {
  proc->fds[orig_fd].flags = (arg & SETFD_VALID_FLAGS);
  return 0;
}

int vfs_fcntl(int fd, int cmd, int arg) {
  process_t* proc = proc_current();
  pmutex_lock(&proc->mu);
  file_t* file = 0x0;
  int result = lookup_fd_locked(fd, &file);
  if (result) {
    pmutex_unlock(&proc->mu);
    return result;
  }

  {
    kmutex_lock(&file->vnode->mutex);
    switch (cmd) {
      case VFS_F_DUPFD:
        result = fcntl_dupfd(proc, file, fd, cmd, arg);
        break;

      case VFS_F_GETFD:
        result = fcntl_getfd(proc, file, fd, cmd, arg);
        break;

      case VFS_F_SETFD:
        result = fcntl_setfd(proc, file, fd, cmd, arg);
        break;

      default:
        result = -EINVAL;
        break;
    }
    kmutex_unlock(&file->vnode->mutex);
  }

  pmutex_unlock(&proc->mu);
  file_unref(file);
  return result;
}
