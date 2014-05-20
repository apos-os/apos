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

#include "vfs/mount.h"

#include "common/errno.h"
#include "vfs/vfs_internal.h"

int vfs_mount_fs(const char* path, fs_t* fs) {
  if (!path || !fs) return -EINVAL;

  // First open the vnode that will be the mount point.
  vnode_t* mount_point = 0x0;
  int result = lookup_existing_path(path, &mount_point);
  if (result) return result;

  if (mount_point->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -ENOTDIR;
  }

  // TODO(aoates): check if its empty.

  // Find a free filesystem slot.
  int fs_idx;
  for (fs_idx = 0; fs_idx < VFS_MAX_FILESYSTEMS; ++fs_idx) {
    if (!g_fs_table[fs_idx].fs) break;
  }
  if (fs_idx >= VFS_MAX_FILESYSTEMS) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -ENOMEM;
  }

  mount_point->mounted_fs = fs_idx;
  fs->id = fs_idx;
  g_fs_table[fs_idx].fs = fs;
  g_fs_table[fs_idx].mount_point = VFS_MOVE_REF(mount_point);

  return 0;
}

int vfs_unmount_fs(const char* path, fs_t** fs_out) {
  return -ENOTSUP;
}
