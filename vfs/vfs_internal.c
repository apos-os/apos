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

mounted_fs_t g_fs_table[VFS_MAX_FILESYSTEMS];
htbl_t g_vnode_cache;
file_t* g_file_table[VFS_MAX_FILES];

int resolve_mounts(vnode_t** vnode) {
  vnode_t* n = *vnode;

  // If the vnode is a mount point, continue to the child filesystem.
  while (n->mounted_fs != VFS_FSID_NONE) {
    // TODO(aoates): check that each of these is valid.
    fs_t* const child_fs = g_fs_table[n->mounted_fs].fs;
    vnode_t* child_fs_root = vfs_get(child_fs, child_fs->get_root(child_fs));
    VFS_PUT_AND_CLEAR(n);
    n = VFS_MOVE_REF(child_fs_root);
  }

  *vnode = n;
  return 0;
}

void resolve_mounts_up(vnode_t** parent, const char* child_name) {
  // If we're traversing past the root node of a mounted filesystem, swap in the
  // mount point.
  while (kstrcmp(child_name, "..") == 0 &&
         (*parent)->parent_mount_point != 0x0) {
    vnode_t* new_parent = VFS_COPY_REF((*parent)->parent_mount_point);
    VFS_PUT_AND_CLEAR(*parent);
    *parent = VFS_MOVE_REF(new_parent);
  }
}

int resolve_symlink(vnode_t* parent, vnode_t** child_ptr) {
  vnode_t* child = *child_ptr;
  while (child->type == VNODE_SYMLINK) {
    char symlink_target[VFS_MAX_PATH_LENGTH];
    if (ENABLE_KERNEL_SAFETY_NETS) {
      kmemset(symlink_target, 0, VFS_MAX_PATH_LENGTH);
    }
    int error = child->fs->readlink(child, symlink_target, VFS_MAX_PATH_LENGTH);
    if (error < 0) return error;
    symlink_target[error] = '\0';

    // TODO(aoates): limit number of recursions.
    vnode_t* symlink_target_node = 0x0;
    error = lookup_existing_path_with_root(parent, symlink_target,
                                           &symlink_target_node, 1);
    if (error) return error;

    VFS_PUT_AND_CLEAR(child);
    child = VFS_MOVE_REF(symlink_target_node);
  }
  *child_ptr = child;
  return 0;
}

int lookup_locked(vnode_t* parent, const char* name, vnode_t** child_out) {
  kmutex_assert_is_held(&parent->mutex);
  int child_inode = parent->fs->lookup(parent, name);

  if (child_inode < 0) {
    return child_inode;
  }

  *child_out = vfs_get(parent->fs, child_inode);
  if (!*child_out) return -EINVAL;
  return 0;
}

int lookup(vnode_t** parent, const char* name, vnode_t** child_out) {
  resolve_mounts_up(parent, name);

  kmutex_lock(&(*parent)->mutex);
  const int result = lookup_locked(*parent, name, child_out);
  kmutex_unlock(&(*parent)->mutex);
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
    int error = lookup(&n, base_name_out, &child);
    if (error) {
      VFS_PUT_AND_CLEAR(n);
      return error;
    }

    error = resolve_symlink(n, &child);
    VFS_PUT_AND_CLEAR(n);
    if (error) {
      VFS_PUT_AND_CLEAR(child);
      return error;
    }

    if (child->type != VNODE_DIRECTORY) {
      VFS_PUT_AND_CLEAR(child);
      return -ENOTDIR;
    }

    error = resolve_mounts(&child);
    if (error) {
      VFS_PUT_AND_CLEAR(child);
      return error;
    }

    // Move to the child and keep going.
    n = VFS_MOVE_REF(child);
    path = name_end;
  }
}

int lookup_existing_path(const char* path, vnode_t** child_out,
                         int resolve_mount) {
  if (!path) return -EINVAL;
  vnode_t* root = get_root_for_path(path);
  int result =
      lookup_existing_path_with_root(root, path, child_out, resolve_mount);
  VFS_PUT_AND_CLEAR(root);
  return result;
}

int lookup_existing_path_with_root(vnode_t* root, const char* path,
                                   vnode_t** child_out, int resolve_mount) {
  if (!path) return -EINVAL;

  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, &parent, base_name);
  if (error) {
    return error;
  }

  // Lookup the child inode.
  vnode_t* child;
  if (base_name[0] == '\0') {
    child = VFS_MOVE_REF(parent);
  } else {
    error = lookup(&parent, base_name, &child);
    VFS_PUT_AND_CLEAR(parent);
    if (error < 0) {
      return error;
    }
  }

  if (resolve_mount) {
    error = resolve_mounts(&child);
    if (error) {
      VFS_PUT_AND_CLEAR(child);
      return error;
    }
  }

  *child_out = child;
  return 0;
}

int lookup_fd(int fd, file_t** file_out) {
  process_t* proc = proc_current();
  if (fd < 0 || fd >= PROC_MAX_FDS || proc->fds[fd] == PROC_UNUSED_FD) {
    return -EBADF;
  }

  file_t* file = g_file_table[proc->fds[fd]];
  KASSERT(file != 0x0);
  *file_out = file;
  return 0;
}

vnode_t* get_root_for_path(const char* path) {
  if (path[0] == '/') {
    fs_t* const root_fs = g_fs_table[VFS_ROOT_FS].fs;
    return vfs_get(root_fs, root_fs->get_root(root_fs));
  } else {
    return VFS_COPY_REF(proc_current()->cwd);
  }
}
