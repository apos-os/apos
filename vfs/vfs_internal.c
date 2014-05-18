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

#include "vfs/vfs_internal.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "vfs/dirent.h"
#include "vfs/fs.h"
#include "vfs/vfs_mode.h"
#include "vfs/vnode.h"
#include "vfs/vfs.h"

fs_t* g_root_fs = 0;
htbl_t g_vnode_cache;
file_t* g_file_table[VFS_MAX_FILES];

int lookup_locked(vnode_t* parent, const char* name, vnode_t** child_out) {
  kmutex_assert_is_held(&parent->mutex);
  int child_inode = parent->fs->lookup(parent, name);

  if (child_inode < 0) {
    return child_inode;
  }

  *child_out = vfs_get(parent->fs, child_inode);
  return 0;
}

int lookup(vnode_t* parent, const char* name, vnode_t** child_out) {
  kmutex_lock(&parent->mutex);
  const int result = lookup_locked(parent, name, child_out);
  kmutex_unlock(&parent->mutex);
  return result;
}

int lookup_by_inode(vnode_t* parent, int inode, char* name_out, int len) {
  KMUTEX_AUTO_LOCK(parent_lock, &parent->mutex);
  const int kBufSize = 512;
  char dirent_buf[kBufSize];

  int offset = 0;
  dirent_t* ent;
  do {
    const int len = parent->fs->getdents(parent, offset, dirent_buf, kBufSize);
    if (len == 0) {
      // Didn't find any matching nodes :(
      return -ENOENT;
    }

    // Look for a matching dirent.
    int buf_offset = 0;
    do {
      ent = (dirent_t*)(&dirent_buf[buf_offset]);
      buf_offset += ent->length;
    } while (ent->vnode != inode && buf_offset < len);
    // Keep going until we find a match.
    offset = ent->offset;
  } while (ent->vnode != inode);

  // Found a match, copy its name.
  const int name_len = kstrlen(ent->name);
  if (len < name_len + 1) {
    return -ERANGE;
  }

  kstrcpy(name_out, ent->name);
  return name_len;
}

int lookup_path(vnode_t* root, const char* path,
                vnode_t** parent_out, char* base_name_out) {
  if (!*path) {
    return -EINVAL;
  }

  vnode_t* n = VFS_COPY_REF(root);

  // Skip leading '/'.
  while (*path && *path == '/') path++;

  if (!*path) {
    // The path was the root node.  We don't check for search permissions since
    // the caller will check permissions on the directory itself.
    *parent_out = VFS_MOVE_REF(n);
    *base_name_out = '\0';
    return 0;
  }

  while(1) {
    // Ensure we have permission to search this directory.
    int mode_check;
    if ((mode_check = vfs_check_mode(
                VFS_OP_SEARCH, proc_current(), n))) {
      VFS_PUT_AND_CLEAR(n);
      return mode_check;
    }

    KASSERT(*path);
    const char* name_end = kstrchrnul(path, '/');
    if (name_end - path >= VFS_MAX_FILENAME_LENGTH) {
      VFS_PUT_AND_CLEAR(n);
      return -ENAMETOOLONG;
    }

    kstrncpy(base_name_out, path, name_end - path);
    base_name_out[name_end - path] = '\0';

    // Advance past any trailing slashes.
    while (*name_end && *name_end == '/') name_end++;

    // Are we at the end?
    if (!*name_end) {
      // Don't vfs_put() the parent, since we want to return it with a refcount.
      *parent_out = VFS_MOVE_REF(n);
      return 0;
    }

    // Otherwise, descend again.
    vnode_t* child = 0x0;
    int error = lookup(n, base_name_out, &child);
    VFS_PUT_AND_CLEAR(n);
    if (error) {
      return error;
    }

    // TODO(aoates): symlink
    if (child->type != VNODE_DIRECTORY) {
      VFS_PUT_AND_CLEAR(child);
      return -ENOTDIR;
    }

    // Move to the child and keep going.
    n = VFS_MOVE_REF(child);
    path = name_end;
  }
}

int lookup_existing_path(const char*path, vnode_t** child_out) {
  if (!path) return -EINVAL;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  // Lookup the child inode.
  vnode_t* child;
  if (base_name[0] == '\0') {
    child = VFS_MOVE_REF(parent);
  } else {
    kmutex_lock(&parent->mutex);
    error = lookup_locked(parent, base_name, &child);
    if (error < 0) {
      kmutex_unlock(&parent->mutex);
      VFS_PUT_AND_CLEAR(parent);
      return error;
    }

    // Done with the parent.
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
  }

  *child_out = child;
  return 0;
}

vnode_t* get_root_for_path(const char* path) {
  if (path[0] == '/') {
    return vfs_get(g_root_fs, g_root_fs->get_root(g_root_fs));
  } else {
    return VFS_COPY_REF(proc_current()->cwd);
  }
}
