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
#include "proc/kthread.h"
#include "proc/pmutex.h"
#include "proc/spinlock.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/fs.h"
#include "vfs/vfs_mode.h"
#include "vfs/vnode.h"
#include "vfs/vfs.h"

mounted_fs_t g_fs_table[VFS_MAX_FILESYSTEMS];
// Protects g_fs_table, serializing mount operations.
kmutex_t g_fs_table_lock;
htbl_t g_vnode_cache GUARDED_BY(g_vnode_cache_lock);
kspinlock_t g_vnode_cache_lock = KSPINLOCK_NORMAL_INIT_STATIC;
file_t* g_file_table[VFS_MAX_FILES];
pmutex_t g_file_table_mu;

static int lookup_path_internal(vnode_t* root, const char* path,
                                lookup_options_t opt, vnode_t** parent_out,
                                vnode_t** child_out, char* base_name_out,
                                int max_recursion);

int resolve_mounts(vnode_t** vnode) {
  vnode_t* n = *vnode;

  // If the vnode is a mount point, continue to the child filesystem.
  kmutex_lock(&n->mutex);
  while (n->mounted_fs != VFS_FSID_NONE) {
    // TODO(aoates): check that each of these is valid.
    fs_t* const child_fs = g_fs_table[n->mounted_fs].fs;
    vnode_t* child_fs_root = vfs_get(child_fs, child_fs->get_root(child_fs));
    KASSERT_DBG(child_fs_root->parent_mount_point == n);
    kmutex_unlock(&n->mutex);
    VFS_PUT_AND_CLEAR(n);
    n = VFS_MOVE_REF(child_fs_root);
    kmutex_lock(&n->mutex);
  }
  kmutex_unlock(&n->mutex);

  *vnode = n;
  return 0;
}

void resolve_mounts_up(vnode_t** parent, const char* child_name) {
  // If we're traversing past the root node of a mounted filesystem, swap in the
  // mount point.
  if (kstrcmp(child_name, "..") != 0) {
    return;
  }

  // N.B.(aoates): not clear if this lock is necessary --- we hold a ref on the
  // parent, so no one should be able to unmount this simultaneously.
  kmutex_lock(&(*parent)->mutex);
  while ((*parent)->parent_mount_point != 0x0) {
    vnode_t* new_parent = VFS_COPY_REF((*parent)->parent_mount_point);
    kmutex_unlock(&(*parent)->mutex);
    VFS_PUT_AND_CLEAR(*parent);
    *parent = VFS_MOVE_REF(new_parent);
    kmutex_lock(&(*parent)->mutex);
  }
  kmutex_unlock(&(*parent)->mutex);
}

int resolve_symlink(bool at_last_element, lookup_options_t opt,
                    vnode_t** parent_ptr, vnode_t** child_ptr,
                    char* base_name_out, int max_recursion) {
  vnode_t* child = *child_ptr;
  vnode_t* parent = VFS_COPY_REF(*parent_ptr);
  char* symlink_target = 0x0;
  while (child && child->type == VNODE_SYMLINK) {
    if (!symlink_target) symlink_target = kmalloc(VFS_MAX_PATH_LENGTH + 1);

    kmutex_lock(&child->mutex);
    int error = child->fs->readlink(child, symlink_target, VFS_MAX_PATH_LENGTH);
    kmutex_unlock(&child->mutex);
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
    opt.lock_on_noent = opt.lock_on_noent && at_last_element;
    error = lookup_path_internal(root, symlink_target, opt,
                                 &new_parent, &symlink_target_node,
                                 base_name_out, max_recursion - 1);
    VFS_PUT_AND_CLEAR(root);
    VFS_PUT_AND_CLEAR(parent);
    if (error) {
      kfree(symlink_target);
      return error;
    }
    if (!at_last_element && !error && !symlink_target_node) {
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
  kmutex_lock(&parent->mutex);
  const int kBufSize = 512;
  char dirent_buf[kBufSize];

  int offset = 0;
  kdirent_t* ent;
  do {
    const int len = parent->fs->getdents(parent, offset, dirent_buf, kBufSize);
    if (len == 0) {
      // Didn't find any matching nodes :(
      kmutex_unlock(&parent->mutex);
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
    kmutex_unlock(&parent->mutex);
    return -ERANGE;
  }

  kstrcpy(name_out, ent->d_name);
  kmutex_unlock(&parent->mutex);
  return name_len;
}

// TODO(aoates): look for a way to express this locking (partially or fully)
static int lookup_path_internal(vnode_t* root, const char* path,
                                lookup_options_t opt, vnode_t** parent_out,
                                vnode_t** child_out, char* base_name_out,
                                int max_recursion) NO_THREAD_SAFETY_ANALYSIS {
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
    resolve_mounts_up(&n, base_name_out);
    kmutex_lock(&n->mutex);
    int error = lookup_locked(n, base_name_out, &child);
    if (error && (!at_last_element || error != -ENOENT)) {
      kmutex_unlock(&n->mutex);
      VFS_PUT_AND_CLEAR(n);
      return error;
    } else if (at_last_element && error == -ENOENT) {
      if (!opt.lock_on_noent)  {
        kmutex_unlock(&n->mutex);
      }
      if (parent_out) *parent_out = VFS_COPY_REF(n);
      if (child_out) *child_out = 0x0;
      VFS_PUT_AND_CLEAR(n);
      return 0;
    }
    kmutex_unlock(&n->mutex);

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
                         vnode_t** child_out) {
  if (!path) return -EINVAL;
  vnode_t* root = get_root_for_path(path);
  char unused_basename[VFS_MAX_FILENAME_LENGTH];
  int result = lookup_path(root, path, opt, NULL,
                           child_out, unused_basename);
  VFS_PUT_AND_CLEAR(root);
  if (!result && !*child_out) {
    return -ENOENT;
  }
  return result;
}

// TODO(aoates): look for a way to express this locking (partially or fully)
int lookup_existing_path_and_lock(
    vnode_t* root, const char* path, lookup_options_t options,
    vnode_t** parent_out, vnode_t** child_out,
    char* base_name_out) NO_THREAD_SAFETY_ANALYSIS {
  const int kMaxRetries = 10;
  KASSERT_DBG(parent_out != NULL);
  KASSERT_DBG(child_out != NULL);
  KASSERT_DBG(options.resolve_final_symlink == false);
  KASSERT_DBG(options.resolve_final_mount == false);

  int result =
      lookup_path(root, path, options, parent_out, child_out, base_name_out);
  if (result) {
    return result;
  } else if (*child_out == NULL) {
    VFS_PUT_AND_CLEAR(*parent_out);
    return -ENOENT;
  }

  // We have a parent and child.  Lock them both, then redo the lookup to ensure
  // confirm the child we have is still bound to that name.  This technically is
  // susceptible to ABA problems, but they're harmless.
  //
  // Note: in theory this could be inlined in lookup_path(), and possibly save
  // ourselves a second lookup, but that would make lookup_path pretty
  // (more?) spaghetti-ish.
  int attempts_left = kMaxRetries;
  while (--attempts_left > 0) {
    // N.B.(aoates): we don't do a resolve_mounts_up call here, though maybe we
    // should for consistency with what happens in lookup_path() --- e.g. if the
    // directory we're in is the root directory of a mounted filesystem that is
    // being moved.
    vfs_lock_vnodes(*parent_out, *child_out);

    // TODO(aoates): need to re-check search perms on the parent here.

    if (*base_name_out == '\0') {
      // Root directory.
      KASSERT_DBG(*parent_out == *child_out);
      return 0;
    }

    vnode_t* new_child = NULL;
    result = lookup_locked(*parent_out, base_name_out, &new_child);
    if (result < 0) {
      vfs_unlock_vnodes(*parent_out, *child_out);
      VFS_PUT_AND_CLEAR(*parent_out);
      VFS_PUT_AND_CLEAR(*child_out);
      return result;
    }

    if (new_child == *child_out) {
      KASSERT_DBG(*child_out != NULL);
      VFS_PUT_AND_CLEAR(new_child);  // Ditch second ref.
      // Return with parent and child locked.
      return 0;
    }

    // The binding changed from under us...unlock, unref the old child, and try
    // again.
    klogfm(KL_VFS, DEBUG,
           "vfs: child changed during lookup (fs=%d parent=%d name='%s' "
           "old_child=%d new_child=%d)\n",
           (*parent_out)->fs->id, (*parent_out)->num, base_name_out,
           (*child_out)->num, new_child->num);
    vfs_unlock_vnodes(*parent_out, *child_out);
    VFS_PUT_AND_CLEAR(*child_out);
    *child_out = VFS_MOVE_REF(new_child);
  }

  klogfm(KL_VFS, WARNING, "vfs: hit max retries trying to lookup path '%s'\n",
         path);
  VFS_PUT_AND_CLEAR(*parent_out);
  VFS_PUT_AND_CLEAR(*child_out);
  return -EIO;
}

int lookup_fd_locked(int fd, file_t** file_out) {
  process_t* proc = proc_current();
  pmutex_assert_is_held(&proc->mu);
  if (!is_valid_fd(fd) || proc->fds[fd].file == PROC_UNUSED_FD) {
    return -EBADF;
  }

  file_t* file = g_file_table[proc->fds[fd].file];
  KASSERT(file != 0x0);
  // Sanity checks.
  KASSERT_DBG(file->index == proc->fds[fd].file);
  KASSERT_DBG(file->vnode != NULL);
  KASSERT_DBG(refcount_get(&file->refcount) > 0);
  KASSERT_DBG(file->pos >= 0);
  file_ref(file);
  *file_out = file;
  return 0;
}

int lookup_fd(int fd, file_t** file_out) {
  process_t* proc = proc_current();
  pmutex_lock(&proc->mu);
  int result = lookup_fd_locked(fd, file_out);
  pmutex_unlock(&proc->mu);
  return result;
}

int is_absolute_path(const char* path) {
  return path[0] == '/';
}

vnode_t* get_root_for_path(const char* path) {
  process_t* const me = proc_current();
  pmutex_lock(&me->mu);
  vnode_t* cwd = VFS_COPY_REF(me->cwd);
  pmutex_unlock(&me->mu);

  vnode_t* result = get_root_for_path_with_parent(path, cwd);
  VFS_PUT_AND_CLEAR(cwd);
  return result;
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

void vfs_lock_vnodes(vnode_t* A, vnode_t* B) NO_THREAD_SAFETY_ANALYSIS {
  if (A && B) {
    KASSERT_DBG(A->fs == B->fs);
  }
  if (A == B) {
    kmutex_lock(&A->mutex);
  } else if (A < B) {
    if (A) kmutex_lock(&A->mutex);
    if (B) kmutex_lock(&B->mutex);
  } else {
    if (B) kmutex_lock(&B->mutex);
    if (A) kmutex_lock(&A->mutex);
  }
}

void vfs_unlock_vnodes(vnode_t* A, vnode_t* B) NO_THREAD_SAFETY_ANALYSIS {
  if (A == B) {
    kmutex_unlock(&A->mutex);
  } else if (A < B) {
    if (B) kmutex_unlock(&B->mutex);
    if (A) kmutex_unlock(&A->mutex);
  } else {
    if (A) kmutex_unlock(&A->mutex);
    if (B) kmutex_unlock(&B->mutex);
  }
}

static void sort_vnode_ptrs(vnode_t** nodes, size_t n) {
  // Do insertion sort on the array of nodes; it is expected to be small (and,
  // when passed to unlock, likely pre-sorted).
  for (size_t i = 1; i < n; ++i) {
    // Invariant: array up to index |i| is already sorted.
    // Starting at the current "top", move the top element down to its place.
    size_t j = i;
    vnode_t* current = nodes[j];
    while (j > 0 && current < nodes[j-1]) {
      nodes[j] = nodes[j-1];
      j--;
    }
    nodes[j] = current;
  }
}

// TODO(aoates): look for a way to express this locking (partially or fully)
void vfs_lock_vnodes2(vnode_t** nodes, size_t n) NO_THREAD_SAFETY_ANALYSIS {
  sort_vnode_ptrs(nodes, n);

  fs_t* fs = NULL;
  for (size_t i = 0; i < n; ++i) {
    if (i < n - 1) {
      KASSERT_DBG(nodes[i] <= nodes[i+1]);
    }
    if (i > 0 && nodes[i] == nodes[i - 1]) continue;
    if (nodes[i]) {
      if (!fs) {
        fs = nodes[i]->fs;
      } else {
        KASSERT_DBG(nodes[i]->fs == fs);
      }
      kmutex_lock(&nodes[i]->mutex);
    }
  }
}

// TODO(aoates): look for a way to express this locking (partially or fully)
void vfs_unlock_vnodes2(vnode_t** nodes, size_t n) NO_THREAD_SAFETY_ANALYSIS {
  // We have to sort because there may be duplicates and we don't want to
  // double-unlock.
  sort_vnode_ptrs(nodes, n);

  for (size_t i = 0; i < n; ++i) {
    if (i < n - 1) {
      KASSERT_DBG(nodes[i] <= nodes[i+1]);
    }
    if (i > 0 && nodes[i] == nodes[i - 1]) continue;
    if (nodes[i]) {
      kmutex_unlock(&nodes[i]->mutex);
    }
  }
}

void vfs_assert_locked(vnode_t* A, vnode_t* B) {
  kmutex_assert_is_held(&A->mutex);
  kmutex_assert_is_held(&B->mutex);
}
