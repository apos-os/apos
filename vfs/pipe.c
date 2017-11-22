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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/anonfs.h"
#include "vfs/vfs_internal.h"
#include "vfs/vnode.h"
#include "vfs/vfs.h"

int vfs_pipe(int fds[2]) {
  fs_t* const fs = g_fs_table[VFS_FIFO_FS].fs;
  const ino_t fifo_ino = anonfs_create_vnode(fs);

  vnode_t* fifo_vnode = vfs_get(fs, fifo_ino);
  if (!fifo_vnode) {
    klogfm(KL_VFS, DFATAL, "vfs_get() on FIFO anonfs failed");
    return -EIO;
  }
  KASSERT_DBG(fifo_vnode->type == VNODE_FIFO);

  fds[0] = vfs_open_vnode(fifo_vnode, VFS_O_RDONLY, false);
  if (fds[0] < 0) {
    VFS_PUT_AND_CLEAR(fifo_vnode);
    return fds[0];
  }

  fds[1] = vfs_open_vnode(fifo_vnode, VFS_O_WRONLY, false);
  if (fds[1] < 0) {
    VFS_PUT_AND_CLEAR(fifo_vnode);
    if (vfs_close(fds[0])) {
      klogfm(KL_VFS, DFATAL, "vfs_pipe(): unable to close first fd");
    }
    return fds[1];
  }

  VFS_PUT_AND_CLEAR(fifo_vnode);
  return 0;
}
