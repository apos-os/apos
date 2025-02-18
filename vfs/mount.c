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
#include "vfs/fs_types.h"
#include "vfs/vfs_internal.h"

static int vfs_mount_fs_locked(const char* path, fs_t* fs) {
  if (!path || !fs) return -EINVAL;

  if (fs->id != VFS_FSID_NONE) return -EBUSY;
  KASSERT_DBG(fs->open_vnodes == 0);

  // First open the vnode that will be the mount point.
  vnode_t* mount_point = 0x0;
  int result = lookup_existing_path(path, lookup_opt(false), &mount_point);
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

  // TODO(SMP): write a concurrent mount/unmount/resolve test that catches this
  // racing with resolve_mounts().
  kmutex_lock(&mount_point->mutex);

  // Lookup should have resolved all mounts.
  KASSERT(mount_point->mounted_fs == VFS_FSID_NONE);
  mount_point->mounted_fs = fs_idx;
  fs->id = fs_idx;
  g_fs_table[fs_idx].fs = fs;
  g_fs_table[fs_idx].mount_point = VFS_COPY_REF(mount_point);
  g_fs_table[fs_idx].mounted_root = vfs_get(fs, fs->get_root(fs));

  // No need to lock the mounted_root, I think --- no one can get to it except
  // via the mount_point, which _is_ locked.
  KASSERT_DBG(g_fs_table[fs_idx].mounted_root->parent_mount_point == 0x0);
  g_fs_table[fs_idx].mounted_root->parent_mount_point =
      VFS_COPY_REF(g_fs_table[fs_idx].mount_point);

  kmutex_unlock(&mount_point->mutex);
  VFS_PUT_AND_CLEAR(mount_point);
  return 0;
}

int vfs_mount_fs(const char* path, fs_t* fs) {
  // TODO(SMP): write a concurrent mount/unmount test.
  kmutex_lock(&g_fs_table_lock);
  int result = vfs_mount_fs_locked(path, fs);
  kmutex_unlock(&g_fs_table_lock);
  return result;
}

// Attempt to flush and put all open vnodes in the filesystem.  This is kludgy
// and ineffecient (and a great way to DoS the system, by just trying to unmount
// a busy filesystem).
//
// If there is concurrent filesystem activity, correctness but not progress is
// guaranteed.  This assumes that if there is no concurrent activity, the order
// of the fs vnode list is not changed (vnodes only removed from the middle).
//
// TODO(SMP): write a highly-concurrent test for this that throws a lot of
// threads doing a lot of different things simultaneously at this logic.
static void try_free_all_open(mounted_fs_t* fs) {
  kspin_lock(&g_vnode_cache_lock);
  list_link_t* link = fs->fs->open_vnodes_list.head;
  // There should always be at least one open vnode when this is called (the
  // mounted root).
  KASSERT_MSG(link != NULL, "FS should have at least one open vnode");
  vnode_t* node = container_of(link, vnode_t, fs_link);
  // Note: we don't have a ref on the node right now!  Save the number, then
  // get it properly.  This is sorta gross --- but avoids us having to muck
  // around with the vnode cache internals too much.  It's possible that the
  // fs node list gets changed while we're doing this, but that's fine --- we
  // don't guarantee progress/completion in that case.
  int node_num = node->num;
  kspin_unlock(&g_vnode_cache_lock);
  while (node_num >= 0) {
    node = vfs_get(fs->fs, node_num);
    // TODO(SMP): write a test that catches this case.
    if (!node) {
      // Eh, someone modified concurrently.  Give up.
      return;
    }
    // Note: no guarantee this is actually the same node as above!  That's fine.
    // At least we know it's initialized and we have a ref on it.
    int result = block_cache_free_all(&node->memobj);
    if (result) {
      vfs_put(node);
      return;
    }

    kspin_lock(&g_vnode_cache_lock);
    if (node != fs->mounted_root && node->refcount > 1) {
      // Someone still holds a ref.  Give up on the whole thing.
      kspin_unlock(&g_vnode_cache_lock);
      vfs_put(node);
      return;
    }

    link = node->fs_link.next;
    if (link) {
      vnode_t* next_node = container_of(link, vnode_t, fs_link);
      node_num = next_node->num;  // Continue down the list.
    } else {
      node_num = -1;
    }
    kspin_unlock(&g_vnode_cache_lock);
    vfs_put(node);
  }
}

static int vfs_unmount_fs_locked(const char* path, fs_t** fs_out) {
  if (!path || !fs_out) return -EINVAL;

  // First open the vnode that we're trying to unmount.
  vnode_t* mounted_root = 0x0;
  int result = lookup_existing_path(path, lookup_opt(false), &mounted_root);
  if (result) return result;

  if (mounted_root->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(mounted_root);
    return -ENOTDIR;
  }

  // No need to lock the mounted_root here --- it can't be modified unless the
  // fs_table_lock is locked, which we currently hold.
  if (mounted_root->parent_mount_point == 0x0) {
    VFS_PUT_AND_CLEAR(mounted_root);
    return -EINVAL;
  }

  vnode_t* mount_point = VFS_COPY_REF(mounted_root->parent_mount_point);
  VFS_PUT_AND_CLEAR(mounted_root);

  // TODO(aoates): why are the following two checks necessary?  These should
  // always pass, right?  Validate that and change to assertions.
  if (mount_point->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -ENOTDIR;
  }

  if (mount_point->mounted_fs == VFS_FSID_NONE) {
    VFS_PUT_AND_CLEAR(mount_point);
    return -EINVAL;
  }

  kmutex_lock(&mount_point->mutex);
  KASSERT(mount_point->mounted_fs > 0 &&
          mount_point->mounted_fs < VFS_MAX_FILESYSTEMS);
  KASSERT(g_fs_table[mount_point->mounted_fs].mount_point == mount_point);
  KASSERT(g_fs_table[mount_point->mounted_fs].fs->id ==
          mount_point->mounted_fs);
  KASSERT(g_fs_table[mount_point->mounted_fs].mounted_root->parent_mount_point
          == mount_point);

  try_free_all_open(&g_fs_table[mount_point->mounted_fs]);

  // We should have at least one open vnode (the mounted_root reference in the
  // fs table).
  KASSERT_DBG(g_fs_table[mount_point->mounted_fs].fs->open_vnodes >= 1);

  // TODO(aoates): need to lock around the refcount read.
  if (g_fs_table[mount_point->mounted_fs].fs->open_vnodes > 1 ||
      g_fs_table[mount_point->mounted_fs].mounted_root->refcount > 1) {
    kmutex_unlock(&mount_point->mutex);
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
  kmutex_unlock(&mount_point->mutex);
  VFS_PUT_AND_CLEAR(mount_point);

  return 0;
}

int vfs_unmount_fs(const char* path, fs_t** fs_out) {
  kmutex_lock(&g_fs_table_lock);
  int result = vfs_unmount_fs_locked(path, fs_out);
  kmutex_unlock(&g_fs_table_lock);
  return result;
}

int vfs_mount(const char* source, const char* mount_path, const char* type,
              unsigned long flags, const void* data, size_t data_len) {
  fs_t* fs = NULL;
  int result = fs_create(type, source, flags, data, data_len, &fs);
  if (result) {
    return result;
  }

  result = vfs_mount_fs(mount_path, fs);
  if (result) {
    fs->destroy_fs(fs);
    return result;
  }

  return 0;
}

int vfs_unmount(const char* mount_path, unsigned long flags) {
  fs_t* fs = NULL;
  int result = vfs_unmount_fs(mount_path, &fs);
  if (result) {
    return result;
  }

  fs->destroy_fs(fs);
  return 0;
}

int vfs_mounted_fs_count(void) {
  kmutex_lock(&g_fs_table_lock);
  int count = 0;
  for (int fs_idx = 0; fs_idx < VFS_MAX_FILESYSTEMS; ++fs_idx) {
    if (g_fs_table[fs_idx].fs) count++;
  }
  kmutex_unlock(&g_fs_table_lock);
  return count;
}
