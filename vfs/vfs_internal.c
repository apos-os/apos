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
#include "proc/spinlock.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/fs.h"
#include "vfs/vfs_mode.h"
#include "vfs/vnode.h"
#include "vfs/vfs.h"

mounted_fs_t g_fs_table[VFS_MAX_FILESYSTEMS];
htbl_t g_vnode_cache;
kspinlock_t g_vnode_cache_lock = KSPINLOCK_NORMAL_INIT_STATIC;
file_t* g_file_table[VFS_MAX_FILES];

static int lookup_path_internal(vnode_t* root, const char* path,
                                lookup_options_t opt, vnode_t** parent_out,
                                vnode_t** child_out, char* base_name_out,
                                int max_recursion);

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

int resolve_symlink(int allow_nonexistant_final, lookup_options_t opt,
                    vnode_t** parent_ptr, vnode_t** child_ptr,
                    char* base_name_out, int max_recursion) {
  vnode_t* child = *child_ptr;
  vnode_t* parent = VFS_COPY_REF(*parent_ptr);
  char* symlink_target = 0x0;
  while (child && child->type == VNODE_SYMLINK) {
    if (!symlink_target) symlink_target = kmalloc(VFS_MAX_PATH_LENGTH + 1);

    int error = child->fs->readlink(child, symlink_target, VFS_MAX_PATH_LENGTH);
    if (error < 0) {
      kfree(symlink_target);
      VFS_PUT_AND_CLEAR(parent);
      return error;
    }
    KASSERT_DBG(error <= VFS_MAX_PATH_LENGTH);
    symlink_target[error] = '\0';

    vnode_t* symlink_target_node = 0x0;
    vnode_t* new_parent = 0x0;
    vnode_t* root = get_root_for_path_with_parent(symlink_target, parent);
    opt.resolve_final_symlink = false;
    error = lookup_path_internal(root, symlink_target, opt,
                                 &new_parent, &symlink_target_node,
                                 base_name_out, max_recursion - 1);
    VFS_PUT_AND_CLEAR(root);
    VFS_PUT_AND_CLEAR(parent);
    if (error) {
      kfree(symlink_target);
      return error;
    }
    if (!allow_nonexistant_final && !error && !symlink_target_node) {
      kfree(symlink_target);
      VFS_PUT_AND_CLEAR(new_parent);
      return -ENOENT;
    }
    parent = VFS_MOVE_REF(new_parent);

    VFS_PUT_AND_CLEAR(child);
    child = VFS_MOVE_REF(symlink_target_node);
    *child_ptr = child;
    max_recursion--;
  }
  if (symlink_target) kfree(symlink_target);
  VFS_PUT_AND_CLEAR(*parent_ptr);
  *parent_ptr = VFS_MOVE_REF(parent);
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
  KASSERT_DBG(inode >= 0);
  KMUTEX_AUTO_LOCK(parent_lock, &parent->mutex);
  const int kBufSize = 512;
  char dirent_buf[kBufSize];

  int offset = 0;
  kdirent_t* ent;
  do {
    const int len = parent->fs->getdents(parent, offset, dirent_buf, kBufSize);
    if (len == 0) {
      // Didn't find any matching nodes :(
      return -ENOENT;
    }

    // Look for a matching dirent.
    int buf_offset = 0;
    do {
      ent = (kdirent_t*)(&dirent_buf[buf_offset]);
      buf_offset += ent->d_reclen;
    } while (ent->d_ino != (kino_t)inode && buf_offset < len);
    // Keep going until we find a match.
    offset = ent->d_offset;
  } while (ent->d_ino != (kino_t)inode);

  // Found a match, copy its name.
  const int name_len = kstrlen(ent->d_name);
  if (len < name_len + 1) {
    return -ERANGE;
  }

  kstrcpy(name_out, ent->d_name);
  return name_len;
}

static int lookup_path_internal(vnode_t* root, const char* path,
                                lookup_options_t opt, vnode_t** parent_out,
                                vnode_t** child_out, char* base_name_out,
                                int max_recursion) {
  if (!*path) {
    return -ENOENT;
  }
  if (!root || !base_name_out) {
    return -EINVAL;
  }

  if (max_recursion < 0) {
    return -ELOOP;
  }

  vnode_t* n = VFS_COPY_REF(root);

  // Skip leading '/'.
  while (*path && *path == '/') path++;

  if (!*path) {
    // The path was the root node.  We don't check for search permissions since
    // the caller will check permissions on the directory itself.
    if (parent_out) *parent_out = VFS_COPY_REF(n);
    if (child_out) *child_out = VFS_COPY_REF(n);
    VFS_PUT_AND_CLEAR(n);
    *base_name_out = '\0';
    return 0;
  }

  while(1) {
    // Ensure we have permission to search this directory.
    int mode_check;
    if (!opt.check_real_ugid) {
      mode_check = vfs_check_mode(
          VFS_OP_SEARCH, proc_current(), n);
    } else {
      mode_check = vfs_check_mode_rugid(
          VFS_OP_SEARCH, proc_current(), n);
    }
    if (mode_check) {
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
    const int at_last_element = (*name_end == '\0');

    // Lookup the next element.  If it can't be found, and we're at the last
    // element, save the parent and succeed anyways.
    vnode_t* child = 0x0;
    int error = lookup(&n, base_name_out, &child);
    if (error && (!at_last_element || error != -ENOENT)) {
      VFS_PUT_AND_CLEAR(n);
      return error;
    } else if (at_last_element && error == -ENOENT) {
      if (parent_out) *parent_out = VFS_COPY_REF(n);
      if (child_out) *child_out = 0x0;
      VFS_PUT_AND_CLEAR(n);
      return 0;
    }

    // If we're not at the end, or we want to follow the final symlink, attempt
    // to resolve it.
    if (!at_last_element || opt.resolve_final_symlink) {
      error = resolve_symlink(at_last_element, opt, &n, &child, base_name_out,
                              max_recursion);
      if (error) {
        VFS_PUT_AND_CLEAR(n);
        VFS_PUT_AND_CLEAR(child);
        return error;
      }

      if (!child) {
        if (parent_out) *parent_out = VFS_COPY_REF(n);
        if (child_out) *child_out = 0x0;
        VFS_PUT_AND_CLEAR(n);
        return 0;
      }
    }

    if (at_last_element && parent_out) *parent_out = VFS_COPY_REF(n);
    VFS_PUT_AND_CLEAR(n);

    if (!at_last_element || opt.resolve_final_mount) {
      error = resolve_mounts(&child);
      if (error) {
        VFS_PUT_AND_CLEAR(child);
        return error;
      }
    }

    // If we're done, we're done.
    if (at_last_element) {
      if (child_out) *child_out = VFS_COPY_REF(child);
      VFS_PUT_AND_CLEAR(child);
      return 0;
    }

    // Otherwise, descend again.
    if (child->type != VNODE_DIRECTORY) {
      VFS_PUT_AND_CLEAR(child);
      return -ENOTDIR;
    }

    // Move to the child and keep going.
    n = VFS_MOVE_REF(child);
    path = name_end;
  }
}

int lookup_path(vnode_t* root, const char* path, lookup_options_t opt,
                vnode_t** parent_out, vnode_t** child_out,
                char* base_name_out) {
  return lookup_path_internal(root, path, opt, parent_out,
                              child_out, base_name_out, VFS_MAX_LINK_RECURSION);
}


int lookup_existing_path(const char* path, lookup_options_t opt,
                         vnode_t** parent_out, vnode_t** child_out) {
  if (!path) return -EINVAL;
  vnode_t* root = get_root_for_path(path);
  char unused_basename[VFS_MAX_FILENAME_LENGTH];
  int result = lookup_path(root, path, opt, parent_out,
                           child_out, unused_basename);
  VFS_PUT_AND_CLEAR(root);
  if (!result && !*child_out) {
    if (parent_out) VFS_PUT_AND_CLEAR(*parent_out);
    return -ENOENT;
  }
  return result;
}

int lookup_fd(int fd, file_t** file_out) {
  process_t* proc = proc_current();
  if (!is_valid_fd(fd) || proc->fds[fd] == PROC_UNUSED_FD) {
    return -EBADF;
  }

  file_t* file = g_file_table[proc->fds[fd]];
  KASSERT(file != 0x0);
  file_ref(file);
  *file_out = file;
  return 0;
}

int is_absolute_path(const char* path) {
  return path[0] == '/';
}

vnode_t* get_root_for_path(const char* path) {
  return get_root_for_path_with_parent(path, proc_current()->cwd);
}

vnode_t* get_root_for_path_with_parent(const char* path,
                                       vnode_t* relative_root) {
  if (is_absolute_path(path)) {
    fs_t* const root_fs = g_fs_table[VFS_ROOT_FS].fs;
    return vfs_get(root_fs, root_fs->get_root(root_fs));
  } else {
    return VFS_COPY_REF(relative_root);
  }
}
