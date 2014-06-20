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
#include "common/kassert.h"
#include "vfs/vfs_internal.h"

int vfs_mount_fs(const char* path, fs_t* fs) {
  if (!path || !fs) return -EINVAL;

  if (fs->id != VFS_FSID_NONE) return -EBUSY;
  KASSERT_DBG(fs->open_vnodes == 0);

  // First open the vnode that will be the mount point.
  vnode_t* mount_point = 0x0;
  int result = lookup_existing_path(path, 0x0, &mount_point, 1);
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
  g_fs_table[fs_idx].mounted_root = vfs_get(fs, fs->get_root(fs));

  KASSERT_DBG(g_fs_table[fs_idx].mounted_root->parent_mount_point == 0x0);
  g_fs_table[fs_idx].mounted_root->parent_mount_point =
      VFS_COPY_REF(g_fs_table[fs_idx].mount_point);

  return 0;
}

int vfs_unmount_fs(const char* path, fs_t** fs_out) {
  if (!path || !fs_out) return -EINVAL;

  // First open the vnode that we're trying to unmount.
  vnode_t* mounted_root = 0x0;
  int result = lookup_existing_path(path, 0x0, &mounted_root, 1);
  if (result) return result;

  if (mounted_root->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(mounted_root);
    return -ENOTDIR;
  }

  if (mounted_root->parent_mount_point == 0x0) {
    VFS_PUT_AND_CLEAR(mounted_root);
    return -EINVAL;
  }

  vnode_t* mount_point = VFS_COPY_REF(mounted_root->parent_mount_point);
  VFS_PUT_AND_CLEAR(mounted_root);
  if (mount_point->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -ENOTDIR;
  }

  if (mount_point->mounted_fs == VFS_FSID_NONE) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -EINVAL;
  }

  KASSERT(mount_point->mounted_fs > 0 &&
          mount_point->mounted_fs < VFS_MAX_FILESYSTEMS);
  KASSERT(g_fs_table[mount_point->mounted_fs].mount_point == mount_point);
  KASSERT(g_fs_table[mount_point->mounted_fs].fs->id ==
          mount_point->mounted_fs);
  KASSERT(g_fs_table[mount_point->mounted_fs].mounted_root->parent_mount_point
          == mount_point);

  // We should have at least one open vnode (the mounted_root reference in the
  // fs table).
  KASSERT_DBG(g_fs_table[mount_point->mounted_fs].fs->open_vnodes >= 1);

  if (g_fs_table[mount_point->mounted_fs].fs->open_vnodes > 1 ||
      g_fs_table[mount_point->mounted_fs].mounted_root->refcount > 1) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -EBUSY;
  }

  *fs_out = g_fs_table[mount_point->mounted_fs].fs;

  VFS_PUT_AND_CLEAR(
      g_fs_table[mount_point->mounted_fs].mounted_root->parent_mount_point);
  VFS_PUT_AND_CLEAR(g_fs_table[mount_point->mounted_fs].mounted_root);

  VFS_PUT_AND_CLEAR(g_fs_table[mount_point->mounted_fs].mount_point);
  g_fs_table[mount_point->mounted_fs].fs->id = VFS_FSID_NONE;
  g_fs_table[mount_point->mounted_fs].fs = 0x0;
  mount_point->mounted_fs = VFS_FSID_NONE;
  VFS_PUT_AND_CLEAR(mount_point);

  return 0;
}

int vfs_mounted_fs_count(void) {
  int count = 0;
  for (int fs_idx = 0; fs_idx < VFS_MAX_FILESYSTEMS; ++fs_idx) {
    if (g_fs_table[fs_idx].fs) count++;
  }
  return count;
}
