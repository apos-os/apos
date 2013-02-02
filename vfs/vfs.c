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
#include "common/hashtable.h"
#include "common/kstring.h"
#include "kmalloc.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "vfs/dirent.h"
#include "vfs/file.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs.h"

void vfs_vnode_init(vnode_t* n) {
  n->num = -1;
  n->type = -1;
  n->len = -1;
  n->refcount = 0;
  kmutex_init(&n->mutex);
}

#define VNODE_CACHE_SIZE 1000

static const char* VNODE_TYPE_NAME[] = {
  "INV", "REG", "DIR"
};

static fs_t* g_root_fs = 0;
static htbl_t g_vnode_cache;
static file_t* g_file_table[VFS_MAX_FILES];

// Helpers for putting and adopting references.  Prefer these to using
// vfs_put(x) and y = x directly.  You should never write ptr = value directly,
// instead using either ptr = VFS_COPY_REF(val) (if you want to acquire a new
// reference and increase the refcount), or VFS_MOVE_REF(val) (if you want to
// move an existing reference into a new location).

// Calls vfs_put() and NULLs out the vnode_t* to prevent future use.
#define VFS_PUT_AND_CLEAR(x) do { \
  vnode_t** const _x = &(x); \
  vfs_put(*_x); \
  *_x = 0x0; \
} while (0)

// Copy an existing vnode reference.
static inline vnode_t* VFS_COPY_REF(vnode_t* ref) {
  vfs_ref(ref);
  return ref;
}

// Move an existing vnode reference into a new variable.
#define VFS_MOVE_REF(x) \
    ({vnode_t** const _x = &(x); \
      vnode_t* const _old_val = *_x; \
      *_x = 0x0; \
      _old_val; })

// Return the index of the next free entry in the file table, or -1 if there's
// no space left.
//
// TODO(aoates): this could be much more efficient.
static int next_free_file_idx() {
  for (int i = 0; i < VFS_MAX_FILES; ++i) {
    if (g_file_table[i] == 0x0) {
      return i;
    }
  }
  return -1;
}

// Return the lowest free fd in the process.
static int next_free_fd(process_t* p) {
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (p->fds[i] == PROC_UNUSED_FD) {
      return i;
    }
  }
  return -1;
}

// Given a vnode and child name, lookup the vnode of the child.  Returns 0 on
// success (and refcounts the child).
//
// Requires a lock on the parent to ensure that the child isn't removed between
// the call to parent->lookup() and vfs_get(child).
static int lookup_locked(vnode_t* parent, const char* name,
                         vnode_t** child_out) {
  kmutex_assert_is_held(&parent->mutex);
  int child_inode = parent->fs->lookup(parent, name);

  if (child_inode < 0) {
    return child_inode;
  }

  *child_out = vfs_get(child_inode);
  return 0;
}

// Convenience wrapper that locks the parent around a call to lookup_locked().
static int lookup(vnode_t* parent, const char* name, vnode_t** child_out) {
  kmutex_lock(&parent->mutex);
  const int result = lookup_locked(parent, name, child_out);
  kmutex_unlock(&parent->mutex);
  return result;
}

// Similar to lookup(), but does the reverse: given a directory and an inode
// number, return the corresponding name, if the directory has an entry for
// that inode number.
//
// Returns the length of the name on success, or -error.
static int lookup_by_inode(vnode_t* parent, int inode,
                           char* name_out, int len) {
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

// Given a vnode and a path path/to/myfile relative to that vnode, return the
// vnode_t of the directory part of the path, and copy the base name of the path
// (without any trailing slashes) into base_name_out.
//
// base_nome_out must be AT LEAST VFS_MAX_FILENAME_LENGTH long.
//
// Returns 0 on success, or -error on failure (in which case the contents of
// parent_out and base_name_out are undefined).
//
// Returns *parent_out with a refcount unless there was an error.
// TODO(aoates): this needs to handle symlinks!
// TODO(aoates): things to test:
//  * regular path
//  * root directory
//  * path ending in file
//  * path ending in directory
//  * trailing slashes
//  * no leading slash (?)
//  * non-directory in middle of path (ENOTDIR)
//  * non-existing in middle of path (ENOENT)
static int lookup_path(vnode_t* root, const char* path,
                       vnode_t** parent_out, char* base_name_out) {
  if (!*path) {
    return -EINVAL;
  }

  vnode_t* n = VFS_COPY_REF(root);

  // Skip leading '/'.
  while (*path && *path == '/') path++;

  if (!*path) {
    // The path was the root node.
    *parent_out = VFS_MOVE_REF(n);
    *base_name_out = '\0';
    return 0;
  }

  while(1) {
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

void vfs_init() {
  KASSERT(g_root_fs == 0);
  g_root_fs = ramfs_create_fs();
  htbl_init(&g_vnode_cache, VNODE_CACHE_SIZE);

  for (int i = 0; i < VFS_MAX_FILES; ++i) {
    g_file_table[i] = 0x0;
  }
}

fs_t* vfs_get_root_fs() {
  return g_root_fs;
}

vnode_t* vfs_get_root_vnode() {
  return vfs_get(g_root_fs->get_root(g_root_fs));
}

vnode_t* vfs_get(int vnode_num) {
  vnode_t* vnode;
  int error = htbl_get(&g_vnode_cache, (uint32_t)vnode_num,  (void**)(&vnode));
  if (!error) {
    KASSERT(vnode->num == vnode_num);

    // Increment the refcount, then lock the mutex.  This ensures that the node
    // is initialized (since the thread creating it locks the mutex *before*
    // putting it in the table, and doesn't unlock it until it's initialized).
    vnode->refcount++;
    if (vnode->type == VNODE_INVALID) {
      // TODO(aoates): add an UNINITIALIZED state and use a semaphore for this.
      kmutex_lock(&vnode->mutex);
      kmutex_unlock(&vnode->mutex);
    }

    // The vnode should now be fully initialized.
    // TODO(aoates): we need to handle error cases!  This will currently explode
    // if the vnode wasn't initialized properly.
    KASSERT(vnode->type != VNODE_INVALID);
    return vnode;
  } else {
    // We need to create the vnode and backfill it from disk.
    vnode = g_root_fs->alloc_vnode(g_root_fs);
    vnode->num = vnode_num;
    vnode->type = VNODE_INVALID;
    vnode->len = -1;
    vnode->refcount = 1;
    vnode->fs = g_root_fs;
    kmutex_lock(&vnode->mutex);

    // Put the (unitialized but locked) vnode into the table.
    htbl_put(&g_vnode_cache, (uint32_t)vnode_num, (void*)vnode);

    // This call could block, at which point other threads attempting to access
    // this node will block until we release the mutex.
    error = g_root_fs->get_vnode(vnode);
    if (error) {
      // TODO(aoates): unlock the vnode and remove it from the table!  How do we
      // synchronize this with other threads trying to get this vnode?
      klogf("warning: error when getting inode %d: %s\n",
            vnode_num, errorname(-error));
      kfree(vnode);
      return 0x0;
    }

    kmutex_unlock(&vnode->mutex);
    return vnode;
  }
}

void vfs_ref(vnode_t* n) {
  n->refcount++;
}

void vfs_put(vnode_t* vnode) {
  KASSERT(vnode->type != VNODE_INVALID);  // We must be fully initialized.
  vnode->refcount--;

  // TODO(aoates): instead of greedily freeing the vnode, mark it as unnecessary
  // and only free it later, if we need to.
  KASSERT(vnode->refcount >= 0);
  if (vnode->refcount == 0) {
    KASSERT(0 == htbl_remove(&g_vnode_cache, (uint32_t)vnode->num));
    // TODO(aoates): is this lock/unlock really neccessary?
    kmutex_lock(&vnode->mutex);
    vnode->fs->put_vnode(vnode);
    kmutex_unlock(&vnode->mutex);
    vnode->type = VNODE_INVALID;
    kfree(vnode);
  }
}

static void vfs_log_cache_iter(void* arg, uint32_t key, void* val) {
  vnode_t* vnode = (vnode_t*)val;
  KASSERT(key == (uint32_t)vnode->num);
  klogf("  0x%x { inode: %d  type: %s  len: %d  refcount: %d }\n",
        vnode, vnode->num, VNODE_TYPE_NAME[vnode->type],
        vnode->len, vnode->refcount);
}

void vfs_log_cache() {
  klogf("VFS vnode cache:\n");
  htbl_iterate(&g_vnode_cache, &vfs_log_cache_iter, 0x0);
}

static void vfs_cache_size_iter(void* arg, uint32_t key, void* val) {
  int* counter = (int*)arg;
  vnode_t* vnode = (vnode_t*)val;
  KASSERT(key == (uint32_t)vnode->num);
  (*counter)++;
}

int vfs_cache_size() {
  int size = 0;
  htbl_iterate(&g_vnode_cache, &vfs_cache_size_iter, &size);
  return size;
}

int vfs_get_vnode_refcount_for_path(const char* path) {
  vnode_t* root = vfs_get(g_root_fs->get_root(g_root_fs));
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  KASSERT(path[0] == '/');
  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  vnode_t* child = 0x0;
  if (base_name[0] == '\0') {
    child = VFS_MOVE_REF(parent);
  } else {
    // Lookup the child inode.
    error = lookup(parent, base_name, &child);
    if (error < 0) {
      VFS_PUT_AND_CLEAR(parent);
      return error;
    }
    VFS_PUT_AND_CLEAR(parent);
  }
  const int refcount = child->refcount - 1;
  VFS_PUT_AND_CLEAR(child);
  return refcount;
}

int vfs_open(const char* path, uint32_t flags) {
  vnode_t* root = vfs_get(g_root_fs->get_root(g_root_fs));
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // TODO(aoates): cwd: track current working directory and use that here.
  KASSERT(path[0] == '/');
  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }
  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EISDIR;  // Root directory is verboten.
  }

  // Lookup the child inode.
  vnode_t* child;
  {
    kmutex_lock(&parent->mutex);
    error = lookup_locked(parent, base_name, &child);
    if (error < 0 && error != -ENOENT) {
      kmutex_unlock(&parent->mutex);
      VFS_PUT_AND_CLEAR(parent);
      return error;
    } else if (error == -ENOENT) {
      if (!(flags & VFS_O_CREAT)) {
        kmutex_unlock(&parent->mutex);
        VFS_PUT_AND_CLEAR(parent);
        return error;
      }

      // Create it.
      int child_inode = parent->fs->create(parent, base_name);
      if (child_inode < 0) {
        kmutex_unlock(&parent->mutex);
        VFS_PUT_AND_CLEAR(parent);
        return child_inode;
      }

      child = vfs_get(child_inode);
    }

    // Done with the parent.
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
  }

  // TODO(aoates): apparently on linux, you can open a directory for reading.
  // What does that mean, and should we allow it?
  if (child->type == VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(child);
    return -EISDIR;
  }
  // Allocate a new file_t in the global file table.
  int idx = next_free_file_idx();
  if (idx < 0) {
    VFS_PUT_AND_CLEAR(child);
    return -ENFILE;
  }

  process_t* proc = proc_current();
  int fd = next_free_fd(proc);
  if (fd < 0) {
    VFS_PUT_AND_CLEAR(child);
    return -EMFILE;
  }

  KASSERT(g_file_table[idx] == 0x0);
  g_file_table[idx] = file_alloc();
  g_file_table[idx]->vnode = VFS_MOVE_REF(child);
  g_file_table[idx]->refcount = 1;

  KASSERT(proc->fds[fd] == PROC_UNUSED_FD);
  proc->fds[fd] = idx;
  return fd;
}

int vfs_close(int fd) {
  process_t* proc = proc_current();
  if (fd < 0 || fd >= PROC_MAX_FDS || proc->fds[fd] == PROC_UNUSED_FD) {
    return -EBADF;
  }

  file_t* file = g_file_table[proc->fds[fd]];
  KASSERT(file != 0x0);

  file->refcount--;
  KASSERT(file->refcount >= 0);
  if (file->refcount == 0) {
    // TODO(aoates): is there a race here? Does vfs_put block?  Could another
    // thread reference this fd/file during that time?  Maybe we need to remove
    // it from the table, and mark the GD as PROC_UNUSED_FD first?
    g_file_table[proc->fds[fd]] = 0x0;
    VFS_PUT_AND_CLEAR(file->vnode);
    file_free(file);
  }

  proc->fds[fd] = PROC_UNUSED_FD;
  return 0;
}

int vfs_mkdir(const char* path) {
  vnode_t* root = vfs_get(g_root_fs->get_root(g_root_fs));
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // TODO(aoates): support cwd
  KASSERT(path[0] == '/');
  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EEXIST;  // Root directory!
  }

  // TODO(aoates): do we really need this lock/unlock?
  kmutex_lock(&parent->mutex); // So it doesn't get collected while we wait.
  int child_inode = parent->fs->mkdir(parent, base_name);
  kmutex_unlock(&parent->mutex);
  if (child_inode < 0) {
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;  // Error :(
  }

  // We're done!
  VFS_PUT_AND_CLEAR(parent);
  return 0;
}

int vfs_rmdir(const char* path) {
  vnode_t* root = vfs_get(g_root_fs->get_root(g_root_fs));
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // TODO(aoates): support cwd
  KASSERT(path[0] == '/');
  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EPERM;  // Root directory!
  } else if (kstrcmp(base_name, ".") == 0) {
    VFS_PUT_AND_CLEAR(parent);
    return -EINVAL;
  }

  // TODO(aoates): do we really need this lock/unlock?
  kmutex_lock(&parent->mutex); // So it doesn't get collected while we wait.
  error = parent->fs->rmdir(parent, base_name);
  kmutex_unlock(&parent->mutex);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_unlink(const char* path) {
  vnode_t* root = vfs_get(g_root_fs->get_root(g_root_fs));
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // TODO(aoates): support cwd
  KASSERT(path[0] == '/');
  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  error = parent->fs->unlink(parent, base_name);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_getcwd(char* path_out, int size) {
  if (!path_out || size < 0) {
    return -EINVAL;
  }

  if (size < 2) {
    return -ERANGE;
  }

  int size_out = 0;
  char* cpath = path_out;
  vnode_t* n = VFS_COPY_REF(proc_current()->cwd);

  // Add an initial '/', which will be trailing at the end.
  kstrcpy(cpath, "/");
  cpath++;
  size_out++;
  size--;

  while (n->fs != g_root_fs || n->num != g_root_fs->get_root(g_root_fs)) {
    // First find the parent vnode.
    vnode_t* parent = 0x0;
    int result = lookup(n, "..", &parent);
    if (result < 0) {
      VFS_PUT_AND_CLEAR(n);
      return result;
    }

    const int inode = n->num;
    VFS_PUT_AND_CLEAR(n);

    // ...then get the name of the *current* vnode.
    result = lookup_by_inode(parent, inode, cpath, size);
    // TODO(aoates): handle ENOENT more gracefully.
    if (result < 0) {
      VFS_PUT_AND_CLEAR(parent);
      return result;
    }
    size_out += result;
    cpath += result;
    size -= result;

    // Add a trailing '/'.
    if (size < 2) {
      VFS_PUT_AND_CLEAR(parent);
      return -ERANGE;
    }
    kstrcpy(cpath, "/");
    cpath++;
    size_out++;
    size--;

    // Recur.
    n = VFS_MOVE_REF(parent);
  }

  VFS_PUT_AND_CLEAR(n);

  if (size_out > 1) {
    reverse_path(path_out);
    KASSERT_DBG(path_out[size_out - 1] == '/');
    path_out[size_out - 1] = '\0';
    size_out--;
  }

  return size_out;
}

int vfs_chdir(const char* path) {
  if (!path) {
    return -EINVAL;
  }

  vnode_t* root = 0x0;
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  if (path[0] == '/') {
    root = vfs_get(g_root_fs->get_root(g_root_fs));
  } else {
    root = VFS_COPY_REF(proc_current()->cwd);
  }

  int error = lookup_path(root, path, &parent, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  vnode_t* new_cwd = 0x0;
  if (base_name[0] == '\0') {
    new_cwd = VFS_MOVE_REF(parent);
  } else {
    // Lookup the child inode.
    error = lookup(parent, base_name, &new_cwd);
    if (error < 0) {
      VFS_PUT_AND_CLEAR(parent);
      return error;
    }

    // Done with the parent.
    VFS_PUT_AND_CLEAR(parent);

    if (new_cwd->type != VNODE_DIRECTORY) {
      VFS_PUT_AND_CLEAR(new_cwd);
      return -ENOTDIR;
    }
  }

  // Set new cwd.
  VFS_PUT_AND_CLEAR(proc_current()->cwd);
  proc_current()->cwd = VFS_MOVE_REF(new_cwd);
  return 0;
}
