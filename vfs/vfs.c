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

#include "common/config.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kstring.h"
#include "dev/dev.h"
#include "dev/tty.h"
#include "memory/kmalloc.h"
#include "memory/memobj_vnode.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/session.h"
#include "proc/user.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/anonfs.h"
#include "vfs/file.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/special.h"
#include "vfs/vfs_mode.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs_test_util.h"
#include "vfs/vnode_hash.h"

#if ENABLE_EXT2
#  include "vfs/ext2/ext2.h"
#endif

#define KLOG(...) klogfm(KL_VFS, __VA_ARGS__)

void vfs_vnode_init(vnode_t* n, int num) {
  n->fs = 0x0;
  n->fstype[0] = 0x0;
  n->num = num;
  n->type = VNODE_UNINITIALIZED;
  n->len = -1;
  n->uid = -1;
  n->mode = 0;
  n->mounted_fs = VFS_FSID_NONE;
  n->parent_mount_point = 0x0;
  n->gid = -1;
  n->refcount = 0;
  kmutex_init(&n->mutex);
  memobj_init_vnode(n);
}

void vfs_fs_init(fs_t* fs) {
  kmemset(fs, 0, sizeof(fs_t));
  fs->id = VFS_FSID_NONE;
  fs->open_vnodes = 0;
  fs->dev = makedev(DEVICE_ID_UNKNOWN, DEVICE_ID_UNKNOWN);
}

#define VNODE_CACHE_SIZE 1000

// Return the index of the next free entry in the file table, or -1 if there's
// no space left.
//
// TODO(aoates): this could be much more efficient.
static int next_free_file_idx(void) {
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
  return -EMFILE;
}

// Returns non-zero if the given mode is a valid create mode_t (i.e. can be
// passed to chmod() or as the mode argument to open()).
static int is_valid_create_mode(mode_t mode) {
  return (mode & ~(VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO |
                   VFS_S_ISUID | VFS_S_ISGID | VFS_S_ISVTX)) == 0;
}

static void init_fifo_vnode(vnode_t* vnode) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);
  KASSERT_DBG(vnode->refcount == 1);

  vnode->fifo = (apos_fifo_t*)kmalloc(sizeof(apos_fifo_t));
  fifo_init(vnode->fifo);
}

static void cleanup_fifo_vnode(vnode_t* vnode) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);
  KASSERT_DBG(vnode->refcount == 0);

  fifo_cleanup(vnode->fifo);
  kfree(vnode->fifo);
  vnode->fifo = NULL;
}

void vfs_init() {
  KASSERT(g_fs_table[VFS_ROOT_FS].fs == 0x0);

#if ENABLE_EXT2
  // First try to mount every ATA device as an ext2 fs.
  fs_t* ext2fs = ext2_create_fs();
  int success = 0;
  for (int i = 0; i < DEVICE_MAX_MINOR; ++i) {
    const apos_dev_t dev = makedev(DEVICE_MAJOR_ATA, i);
    if (dev_get_block(dev)) {
      const int result = ext2_mount(ext2fs, dev);
      if (result == 0) {
        KLOG(INFO, "Found ext2 FS on device %d.%d\n", major(dev), minor(dev));
        g_fs_table[VFS_ROOT_FS].fs = ext2fs;
        success = 1;
        break;
      }
    }
  }

  if (!success) {
    KLOG(INFO, "Didn't find any mountable filesystems; mounting ramfs as /\n");
    ext2_destroy_fs(ext2fs);
  }
#endif  // ENABLE_EXT2

  if (!g_fs_table[VFS_ROOT_FS].fs)
    g_fs_table[VFS_ROOT_FS].fs = ramfs_create_fs(1);

  g_fs_table[VFS_ROOT_FS].fs->id = VFS_ROOT_FS;

  // Create the anonymous FIFO filesystem (for pipes).
  g_fs_table[VFS_FIFO_FS].mount_point = NULL;
  g_fs_table[VFS_FIFO_FS].mounted_root = NULL;
  g_fs_table[VFS_FIFO_FS].fs = anonfs_create(VNODE_FIFO);
  g_fs_table[VFS_FIFO_FS].fs->id = VFS_FIFO_FS;

  htbl_init(&g_vnode_cache, VNODE_CACHE_SIZE);

  for (int i = 0; i < VFS_MAX_FILES; ++i) {
    g_file_table[i] = 0x0;
  }

  KASSERT(proc_current()->cwd == 0x0);
  proc_current()->cwd = vfs_get_root_vnode();
}

fs_t* vfs_get_root_fs() {
  return g_fs_table[VFS_ROOT_FS].fs;
}

vnode_t* vfs_get_root_vnode() {
  fs_t* root_fs = vfs_get_root_fs();
  return vfs_get(root_fs, root_fs->get_root(root_fs));
}

vnode_t* vfs_get(fs_t* fs, int vnode_num) {
  vnode_t* vnode;
  int error = htbl_get(&g_vnode_cache, vnode_hash(fs, vnode_num),
                       (void**)(&vnode));
  if (!error) {
    KASSERT(vnode->num == vnode_num);

    // Increment the refcount, then lock the mutex.  This ensures that the node
    // is initialized (since the thread creating it locks the mutex *before*
    // putting it in the table, and doesn't unlock it until it's initialized).
    vnode->refcount++;
    if (vnode->type == VNODE_UNINITIALIZED) {
      // TODO(aoates): use a semaphore for this.
      kmutex_lock(&vnode->mutex);
      kmutex_unlock(&vnode->mutex);
    }

    // If initialization failed, put the node back.  This will free it if we're
    // the last one waiting on it.
    if (vnode->type == VNODE_UNINITIALIZED) {
      vfs_put(vnode);
      return 0x0;
    }

    KASSERT(vnode->type != VNODE_UNINITIALIZED && vnode->type != VNODE_INVALID);
    return vnode;
  } else {
    // We need to create the vnode and backfill it from disk.
    vnode = fs->alloc_vnode(fs);
    vfs_vnode_init(vnode, vnode_num);
    vnode->refcount = 1;
    vnode->fs = fs;
    fs->open_vnodes++;
    kmutex_lock(&vnode->mutex);

    // Put the (unitialized but locked) vnode into the table.
    htbl_put(&g_vnode_cache, vnode_hash_n(vnode), (void*)vnode);

    // This call could block, at which point other threads attempting to access
    // this node will block until we release the mutex.
    error = fs->get_vnode(vnode);

    if (error) {
      // In case the fs overwrote this.  We must do this before we unlock.
      vnode->type = VNODE_UNINITIALIZED;
      KLOG(WARNING, "error when getting inode %d: %s\n",
           vnode_num, errorname(-error));
      kmutex_unlock(&vnode->mutex);
      vfs_put(vnode);
      return 0x0;
    }

    if (vnode->type == VNODE_FIFO)
      init_fifo_vnode(vnode);

    kmutex_unlock(&vnode->mutex);
    return vnode;
  }
}

void vfs_ref(vnode_t* n) {
  n->refcount++;
}

void vfs_put(vnode_t* vnode) {
  KASSERT(vnode->type != VNODE_INVALID);
  vnode->refcount--;

  // TODO(aoates): instead of greedily freeing the vnode, mark it as unnecessary
  // and only free it later, if we need to.
  KASSERT(vnode->refcount >= 0);
  if (vnode->refcount == 0) {
    KASSERT(vnode->memobj.refcount == 0);
    KASSERT(0 == htbl_remove(&g_vnode_cache, vnode_hash_n(vnode)));
    if (vnode->type == VNODE_FIFO) cleanup_fifo_vnode(vnode);

    // Only put the node back into the fs if we were able to fully initialize
    // it.
    if (vnode->type != VNODE_UNINITIALIZED) {
      vnode->fs->put_vnode(vnode);
    }
    vnode->fs->open_vnodes--;
    KASSERT_DBG(vnode->fs->open_vnodes >= 0);
    vnode->type = VNODE_INVALID;
    kfree(vnode);
  }
}

int vfs_get_vnode_dir_path(vnode_t* vnode, char* path_out, int size) {
  KASSERT(vnode);
  if (!path_out || size < 0) {
    return -EINVAL;
  }

  if (size < 2) {
    return -ERANGE;
  }

  if (vnode->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  int size_out = 0;
  char* cpath = path_out;
  vnode_t* n = VFS_COPY_REF(vnode);

  // Add an initial '/', which will be trailing at the end.
  kstrcpy(cpath, "/");
  cpath++;
  size_out++;
  size--;

  fs_t* root_fs = vfs_get_root_fs();
  while (n->fs != root_fs || n->num != root_fs->get_root(root_fs)) {
    // First find the parent vnode.
    vnode_t* parent = 0x0;
    int result = lookup(&n, "..", &parent);
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

// Set the appropriate metadata (mode, owner, group, etc) on the given vnode,
// which is newly created.
static void vfs_set_created_metadata(vnode_t* vnode, mode_t mode) {
  vnode->uid = geteuid();
  vnode->gid = getegid();
  vnode->mode = (mode & ~proc_current()->umask) & ~VFS_S_IFMT;
}

static int vfs_open_fifo(vnode_t* vnode, mode_t mode, bool block) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);

  fifo_mode_t fifo_mode;
  if (mode == VFS_O_RDONLY) fifo_mode = FIFO_READ;
  else if (mode == VFS_O_WRONLY) fifo_mode = FIFO_WRITE;
  else return -EINVAL;

  return fifo_open(vnode->fifo, fifo_mode, block, false /* force */);
}

static void vfs_close_fifo(vnode_t* vnode, mode_t mode) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);

  fifo_mode_t fifo_mode;
  if (mode == VFS_O_RDONLY) fifo_mode = FIFO_READ;
  else if (mode == VFS_O_WRONLY) fifo_mode = FIFO_WRITE;
  else die("invalid mode seen in vfs_close_fifo");

  fifo_close(vnode->fifo, fifo_mode);
}

int vfs_open_vnode(vnode_t* child, int flags, bool block) {
  const mode_t mode = flags & VFS_MODE_MASK;
  if (child->type != VNODE_REGULAR && child->type != VNODE_DIRECTORY &&
      child->type != VNODE_CHARDEV && child->type != VNODE_BLOCKDEV &&
      child->type != VNODE_FIFO) {
    return -ENOTSUP;
  }

  // Directories must be opened read-only.
  if (child->type == VNODE_DIRECTORY && mode != VFS_O_RDONLY) {
    return -EISDIR;
  }

  if ((flags & VFS_O_DIRECTORY) && child->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  if (child->type == VNODE_FIFO) {
    int result = vfs_open_fifo(child, mode, block);
    if (result) {
      return result;
    }
  }

  // Allocate a new file_t in the global file table.
  int idx = next_free_file_idx();
  if (idx < 0) {
    return -ENFILE;
  }

  process_t* proc = proc_current();
  int fd = next_free_fd(proc);
  if (fd < 0) {
    return fd;
  }

  if (child->type == VNODE_CHARDEV && major(child->dev) == DEVICE_MAJOR_TTY &&
      !(flags & VFS_O_NOCTTY)) {
    tty_t* tty = tty_get(child->dev);
    if (!tty) {
      KLOG(DFATAL, "tty_get() failed in vnode open\n");
      return -EIO;
    }
    const sid_t sid = proc_getsid(0);
    proc_session_t* const session = proc_session_get(sid);
    if (sid == proc_current()->id &&
        session->ctty == PROC_SESSION_NO_CTTY && tty->session < 0) {
      KLOG(DEBUG, "allocating TTY %d as controlling terminal for session %d\n",
           minor(child->dev), sid);
      session->ctty = minor(child->dev);
      tty->session = sid;
    }
  }

  KASSERT(g_file_table[idx] == 0x0);
  g_file_table[idx] = file_alloc();
  file_init_file(g_file_table[idx]);
  g_file_table[idx]->vnode = VFS_COPY_REF(child);
  g_file_table[idx]->refcount = 1;
  g_file_table[idx]->mode = mode;
  g_file_table[idx]->flags = flags;

  KASSERT(proc->fds[fd] == PROC_UNUSED_FD);
  proc->fds[fd] = idx;
  return fd;
}

int vfs_open(const char* path, int flags, ...) {
  // Check arguments.
  const uint32_t mode = flags & VFS_MODE_MASK;
  if (mode != VFS_O_RDONLY && mode != VFS_O_WRONLY && mode != VFS_O_RDWR) {
    return -EINVAL;
  }
  mode_t create_mode = 0;
  if (flags & VFS_O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, mode_t);
    va_end(args);
  }

  if (!is_valid_create_mode(create_mode)) return -EINVAL;
  if (mode == VFS_O_RDONLY && (flags & VFS_O_TRUNC)) return -EACCES;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  bool follow_final_symlink =
      !((flags & VFS_O_CREAT) && (flags & VFS_O_EXCL)) &&
      !(flags & VFS_O_NOFOLLOW);
  int error = lookup_path(root, path, lookup_opt(follow_final_symlink), &parent,
                          0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  // If the final component is a '..', try to traverse the mount point.
  resolve_mounts_up(&parent, base_name);

  // Lookup the child inode.
  vnode_t* child;
  int created = 0;
  if (base_name[0] == '\0') {
    child = VFS_COPY_REF(parent);
  } else {
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

      int mode_check = 0;
      mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
      if (mode_check) {
        kmutex_unlock(&parent->mutex);
        VFS_PUT_AND_CLEAR(parent);
        return mode_check;
      }

      // Create it.
      int child_inode =
          parent->fs->mknod(parent, base_name, VNODE_REGULAR, makedev(0, 0));
      if (child_inode < 0) {
        kmutex_unlock(&parent->mutex);
        VFS_PUT_AND_CLEAR(parent);
        return child_inode;
      }

      child = vfs_get(parent->fs, child_inode);
      vfs_set_created_metadata(child, create_mode);
      created = 1;
    } else if ((flags & VFS_O_CREAT) && (flags & VFS_O_EXCL)) {
      kmutex_unlock(&parent->mutex);
      VFS_PUT_AND_CLEAR(parent);
      VFS_PUT_AND_CLEAR(child);
      return -EEXIST;
    }

    // Done with the parent.
    kmutex_unlock(&parent->mutex);
  }
  VFS_PUT_AND_CLEAR(parent);

  error = resolve_mounts(&child);
  if (error) {
    VFS_PUT_AND_CLEAR(child);
    return error;
  }

  // Check permissions on the file if it already exists.
  if (!created) {
    int mode_check = 0;
    if (mode == VFS_O_RDONLY || mode == VFS_O_RDWR) {
      mode_check = vfs_check_mode(VFS_OP_READ, proc_current(), child);
    }
    if (mode_check == 0 && (mode == VFS_O_WRONLY || mode == VFS_O_RDWR)) {
      mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), child);
    }
    if (mode_check == 0 && flags & VFS_O_INTERNAL_EXEC) {
      mode_check = vfs_check_mode(VFS_OP_EXEC, proc_current(), child);
    }
    if (mode_check) {
      VFS_PUT_AND_CLEAR(child);
      return mode_check;
    }
  }

  if (child->type == VNODE_SYMLINK) {
    VFS_PUT_AND_CLEAR(child);
    if (flags & VFS_O_NOFOLLOW) {
      return -ELOOP;
    } else {
      KLOG(ERROR,
           "vfs: got a symlink file in vfs_open('%s') (should have been "
           "resolved)\n",
           path);
      return -EIO;
    }
  }

  const bool block = !(flags & VFS_O_NONBLOCK);
  int result = vfs_open_vnode(child, flags, block);
  VFS_PUT_AND_CLEAR(child);

  if (result >= 0 && flags & VFS_O_TRUNC) {
    int trunc_result = vfs_ftruncate(result, 0);
    if (trunc_result < 0) {
      vfs_close(result);
      result = trunc_result;
    }
  }

  return result;
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
    if (file->vnode->type == VNODE_FIFO)
      vfs_close_fifo(file->vnode, file->mode);

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

int vfs_dup(int orig_fd) {
  file_t* file = 0x0;
  int result = lookup_fd(orig_fd, &file);
  if (result) return result;

  process_t* proc = proc_current();
  int new_fd = next_free_fd(proc);
  if (new_fd < 0) {
    return new_fd;
  }

  file->refcount++;
  KASSERT_DBG(proc->fds[new_fd] == PROC_UNUSED_FD);
  proc->fds[new_fd] = proc->fds[orig_fd];
  return new_fd;
}

int vfs_dup2(int fd1, int fd2) {
  file_t* file1 = 0x0, *file2 = 0x0;
  int result = lookup_fd(fd1, &file1);
  if (result) return result;

  if (!is_valid_fd(fd2)) return -EBADF;

  if (fd1 == fd2) return fd2;

  // Close fd2 if it already exists.
  result = lookup_fd(fd2, &file2);
  if (result == 0) {
    result = vfs_close(fd2);
    if (result) return result;
  }

  process_t* proc = proc_current();

  file1->refcount++;
  KASSERT_DBG(proc->fds[fd2] == PROC_UNUSED_FD);
  proc->fds[fd2] = proc->fds[fd1];
  return fd2;
}

int vfs_mkdir(const char* path, mode_t mode) {
  if (!is_valid_create_mode(mode)) return -EINVAL;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(false), &parent, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EEXIST;  // Root directory!
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  int child_inode = parent->fs->mkdir(parent, base_name);
  if (child_inode < 0) {
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;  // Error :(
  }

  vnode_t* child = vfs_get(parent->fs, child_inode);
  vfs_set_created_metadata(child, mode);
  VFS_PUT_AND_CLEAR(child);

  // We're done!
  VFS_PUT_AND_CLEAR(parent);
  return 0;
}

int vfs_mknod(const char* path, mode_t mode, apos_dev_t dev) {
  if (!VFS_S_ISREG(mode) && !VFS_S_ISCHR(mode) && !VFS_S_ISBLK(mode) &&
      !VFS_S_ISFIFO(mode)) {
    return -EINVAL;
  }

  if (!is_valid_create_mode(mode & ~VFS_S_IFMT)) return -EINVAL;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(false), &parent, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EEXIST;  // Root directory!
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  vnode_type_t type = VNODE_INVALID;
  if (VFS_S_ISREG(mode)) type = VNODE_REGULAR;
  else if (VFS_S_ISBLK(mode)) type = VNODE_BLOCKDEV;
  else if (VFS_S_ISCHR(mode)) type = VNODE_CHARDEV;
  else if (VFS_S_ISFIFO(mode)) type = VNODE_FIFO;
  else die("unknown node type");

  int child_inode = parent->fs->mknod(parent, base_name, type, dev);
  if (child_inode < 0) {
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;  // Error :(
  }

  vnode_t* child = vfs_get(parent->fs, child_inode);
  vfs_set_created_metadata(child, mode & ~VFS_S_IFMT);
  VFS_PUT_AND_CLEAR(child);

  // We're done!
  VFS_PUT_AND_CLEAR(parent);
  return 0;
}

int vfs_rmdir(const char* path) {
  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(false), &parent, 0x0, base_name);
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

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  // Get the child so we can vfs_put() it after calling fs->unlink(), which will
  // collect the inode if it's now unused.
  vnode_t* child = 0x0;
  error = lookup(&parent, base_name, &child);
  if (error) {
    VFS_PUT_AND_CLEAR(parent);
    return error;
  }

  if (child->mounted_fs != VFS_FSID_NONE) {
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EBUSY;
  }

  error = parent->fs->rmdir(parent, base_name);
  VFS_PUT_AND_CLEAR(child);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_link(const char* path1, const char* path2) {
  vnode_t* parent1 = 0x0, *parent2 = 0x0;
  vnode_t* vnode1 = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_existing_path(path1, lookup_opt(false), &parent1, &vnode1);
  if (error) {
    return error;
  }

  if (vnode1->type == VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(vnode1);
    return -EPERM;
  }

  vnode_t* root2 = get_root_for_path(path2);
  error =
      lookup_path(root2, path2, lookup_opt(false), &parent2, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root2);
  if (error) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    return error;
  }

  if (vnode1->fs != parent2->fs) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return -EXDEV;
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent2);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return mode_check;
  }

  error = parent2->fs->link(parent2, vnode1, base_name);
  VFS_PUT_AND_CLEAR(vnode1);
  VFS_PUT_AND_CLEAR(parent1);
  VFS_PUT_AND_CLEAR(parent2);
  return error;
}

// Returns true if A is an ancestor of B.
static bool vfs_is_ancestor(const vnode_t* A, vnode_t* B) {
  KASSERT(A);
  KASSERT(A->type == VNODE_DIRECTORY);
  KASSERT(B);
  KASSERT(B->type == VNODE_DIRECTORY);

  vnode_t* n = VFS_COPY_REF(B);

  fs_t* root_fs = vfs_get_root_fs();
  while (n->fs != root_fs || n->num != root_fs->get_root(root_fs)) {
    if (n == A) {
      VFS_PUT_AND_CLEAR(n);
      return true;
    }

    // First find the parent vnode.
    vnode_t* parent = 0x0;
    int result = lookup(&n, "..", &parent);
    VFS_PUT_AND_CLEAR(n);
    if (result < 0) {
      return result;
    }

    n = VFS_MOVE_REF(parent);
  }

  VFS_PUT_AND_CLEAR(n);

  return false;
}

static void lock_vnodes(vnode_t* A, vnode_t* B) {
  if (A == B) {
    kmutex_lock(&A->mutex);
  } else if (A < B) {
    kmutex_lock(&A->mutex);
    kmutex_lock(&B->mutex);
  } else {
    kmutex_lock(&B->mutex);
    kmutex_lock(&A->mutex);
  }
}

static void unlock_vnodes(vnode_t* A, vnode_t* B) {
  if (A == B) {
    kmutex_unlock(&A->mutex);
  } else if (A < B) {
    kmutex_unlock(&B->mutex);
    kmutex_unlock(&A->mutex);
  } else {
    kmutex_unlock(&A->mutex);
    kmutex_unlock(&B->mutex);
  }
}

int vfs_rename(const char* path1, const char* path2) {
  vnode_t* parent1 = 0x0, *parent2 = 0x0;
  vnode_t* vnode1 = 0x0;
  char base_name1[VFS_MAX_FILENAME_LENGTH];
  char base_name2[VFS_MAX_FILENAME_LENGTH];

  vnode_t* root1 = get_root_for_path(path1);
  int error = lookup_path(root1, path1, lookup_opt(false), &parent1, &vnode1,
                          base_name1);
  VFS_PUT_AND_CLEAR(root1);
  if (error == 0 && !vnode1) {
    VFS_PUT_AND_CLEAR(parent1);
    return -ENOENT;
  } else if (error) {
    return error;
  }

  vnode_t* root2 = get_root_for_path(path2);
  error =
      lookup_path(root2, path2, lookup_opt(false), &parent2, 0x0, base_name2);
  VFS_PUT_AND_CLEAR(root2);
  if (error) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    return error;
  }

  if (vnode1->fs != parent2->fs) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return -EXDEV;
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent2);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return mode_check;
  }

  if (kstrcmp(base_name1, ".") == 0 || kstrcmp(base_name1, "..") == 0 ||
      kstrcmp(base_name2, ".") == 0 || kstrcmp(base_name2, "..") == 0) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return -EINVAL;
  }

  if (vnode1->type == VNODE_DIRECTORY && vfs_is_ancestor(vnode1, parent2)) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return -EINVAL;
  }

  lock_vnodes(parent1, parent2);

  // N.B. this bypasses the resolve_mounts_up() call that lookup() does, but
  // that's fine, since base_name2 will never be ".." (and therefore we'll never
  // be traversing past a mount point).
  vnode_t* vnode2 = 0x0;
  error = lookup_locked(parent2, base_name2, &vnode2);
  if (error != 0 && error != -ENOENT) {
    unlock_vnodes(parent1, parent2);
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return error;
  }

  KASSERT_DBG(path1[0] != '\0');
  KASSERT_DBG(path2[0] != '\0');
  if ((path1[kstrlen(path1) - 1] == '/' && vnode1->type != VNODE_DIRECTORY) ||
      (path2[kstrlen(path2) - 1] == '/' &&
       ((!vnode2 && vnode1->type != VNODE_DIRECTORY) ||
        (vnode2 && vnode2->type != VNODE_DIRECTORY)))) {
    // TODO(aoates): this should test for symlinks to directories as well.
    if (vnode2) VFS_PUT_AND_CLEAR(vnode2);
    unlock_vnodes(parent1, parent2);
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return -ENOTDIR;
  }

  if (vnode2) {
    if (vnode1 == vnode2) {
      unlock_vnodes(parent1, parent2);
      VFS_PUT_AND_CLEAR(vnode2);
      VFS_PUT_AND_CLEAR(vnode1);
      VFS_PUT_AND_CLEAR(parent1);
      VFS_PUT_AND_CLEAR(parent2);
      return 0;
    }

    if (vnode1->type != VNODE_DIRECTORY && vnode2->type == VNODE_DIRECTORY) {
      error = -EISDIR;
    } else if (vnode1->type == VNODE_DIRECTORY &&
               vnode2->type != VNODE_DIRECTORY) {
      error = -ENOTDIR;
    } else if (vnode2->type == VNODE_DIRECTORY) {
      error = parent2->fs->rmdir(parent2, base_name2);
    } else {
      error = parent2->fs->unlink(parent2, base_name2);
    }
    VFS_PUT_AND_CLEAR(vnode2);
    if (error) {
      unlock_vnodes(parent1, parent2);
      VFS_PUT_AND_CLEAR(vnode1);
      VFS_PUT_AND_CLEAR(parent1);
      VFS_PUT_AND_CLEAR(parent2);
      return error;
    }
  }

  error = parent1->fs->unlink(parent1, base_name1);
  if (error) {
    unlock_vnodes(parent1, parent2);
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    VFS_PUT_AND_CLEAR(parent2);
    return error;
  }

  error = parent2->fs->link(parent2, vnode1, base_name2);
  unlock_vnodes(parent1, parent2);
  VFS_PUT_AND_CLEAR(vnode1);
  VFS_PUT_AND_CLEAR(parent1);
  VFS_PUT_AND_CLEAR(parent2);
  return error;
}

int vfs_unlink(const char* path) {
  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(false), &parent, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  // Get the child so we can vfs_put() it after calling fs->unlink(), which will
  // collect the inode if it's now unused.
  vnode_t* child = 0x0;
  error = lookup(&parent, base_name, &child);
  if (error) {
    VFS_PUT_AND_CLEAR(parent);
    return error;
  }

  if (child->type == VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EISDIR;
  }

  error = parent->fs->unlink(parent, base_name);
  VFS_PUT_AND_CLEAR(child);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_read(int fd, void* buf, size_t count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR &&
             file->vnode->type != VNODE_CHARDEV &&
             file->vnode->type != VNODE_BLOCKDEV &&
             file->vnode->type != VNODE_FIFO) {
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_RDONLY && file->mode != VFS_O_RDWR) {
    return -EBADF;
  }
  file->refcount++;

  if (file->vnode->type == VNODE_FIFO) {
    result = fifo_read(file->vnode->fifo, buf, count,
                       !(file->flags & VFS_O_NONBLOCK));
  } else if (file->vnode->type == VNODE_CHARDEV) {
    result = special_device_read(file->vnode->type, file->vnode->dev, file->pos,
                                 buf, count, file->flags);
  } else {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    if (file->vnode->type == VNODE_REGULAR) {
      result = file->vnode->fs->read(file->vnode, file->pos, buf, count);
    } else {
      result = special_device_read(file->vnode->type, file->vnode->dev,
                                   file->pos, buf, count, file->flags);
    }
    if (result >= 0) {
      file->pos += result;
    }
  }

  file->refcount--;
  return result;
}

int vfs_write(int fd, const void* buf, size_t count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR &&
             file->vnode->type != VNODE_CHARDEV &&
             file->vnode->type != VNODE_BLOCKDEV &&
             file->vnode->type != VNODE_FIFO) {
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_WRONLY && file->mode != VFS_O_RDWR) {
    return -EBADF;
  }
  file->refcount++;

  if (file->vnode->type == VNODE_FIFO) {
    result = fifo_write(file->vnode->fifo, buf, count,
                        !(file->flags & VFS_O_NONBLOCK));
  } else if (file->vnode->type == VNODE_CHARDEV) {
    result = special_device_write(file->vnode->type, file->vnode->dev,
                                  file->pos, buf, count, file->flags);
  } else {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    if (file->vnode->type == VNODE_REGULAR) {
      if (file->flags & VFS_O_APPEND) file->pos = file->vnode->len;
      result = file->vnode->fs->write(file->vnode, file->pos, buf, count);
    } else {
      result = special_device_write(file->vnode->type, file->vnode->dev,
                                    file->pos, buf, count, file->flags);
    }
    if (result >= 0) {
      file->pos += result;
    }
  }

  file->refcount--;
  return result;
}

off_t vfs_seek(int fd, off_t offset, int whence) {
  if (whence != VFS_SEEK_SET && whence != VFS_SEEK_CUR &&
      whence != VFS_SEEK_END) {
    return -EINVAL;
  }

  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_FIFO) return -ESPIPE;
  if (file->vnode->type != VNODE_REGULAR &&
      file->vnode->type != VNODE_CHARDEV &&
      file->vnode->type != VNODE_BLOCKDEV) {
    return -ENOTSUP;
  }

  if (file->vnode->type == VNODE_CHARDEV) {
    KASSERT_DBG(file->pos == 0);
    return 0;
  }

  int new_pos = -1;
  switch (whence) {
    case VFS_SEEK_SET: new_pos = offset; break;
    case VFS_SEEK_CUR: new_pos = file->pos + offset; break;
    case VFS_SEEK_END: new_pos = file->vnode->len + offset; break;
  }

  if (new_pos < 0) {
    return -EINVAL;
  } else if (file->vnode->type == VNODE_BLOCKDEV) {
    // Verify that we're in bounds for the device.
    KASSERT(file->vnode->len == 0);
    block_dev_t* dev = dev_get_block(file->vnode->dev);
    if (!dev) return -ENXIO;
    if (new_pos >= dev->sectors * dev->sector_size) return -EINVAL;
  }

  file->pos = new_pos;
  return file->pos;
}

int vfs_getdents(int fd, dirent_t* buf, int count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }
  file->refcount++;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = file->vnode->fs->getdents(file->vnode, file->pos, buf, count);
    if (result >= 0) {
      // Find the last returned dirent_t, and use it's offset.
      dirent_t* ent = buf;
      int bufpos = 0;
      while (bufpos < result) {
        ent = (dirent_t*)((char*)buf + bufpos);
        bufpos += ent->d_reclen;
      }
      file->pos = ent->d_offset;
    }
  }

  file->refcount--;
  return result;
}

int vfs_getcwd(char* path_out, size_t size) {
  // TODO(aoates): size_t all the way down.
  return vfs_get_vnode_dir_path(proc_current()->cwd, path_out, size);
}

int vfs_chdir(const char* path) {
  vnode_t* new_cwd = 0x0;
  int error = lookup_existing_path(path, lookup_opt(true), 0x0, &new_cwd);
  if (error) return error;

  if (new_cwd->type != VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(new_cwd);
    return -ENOTDIR;
  }

  int mode_check =
      vfs_check_mode(VFS_OP_SEARCH, proc_current(), new_cwd);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(new_cwd);
    return mode_check;
  }

  // Set new cwd.
  VFS_PUT_AND_CLEAR(proc_current()->cwd);
  proc_current()->cwd = VFS_MOVE_REF(new_cwd);
  return 0;
}

int vfs_get_memobj(int fd, mode_t mode, memobj_t** memobj_out) {
  *memobj_out = 0x0;
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR) {
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_RDWR && file->mode != mode) {
    return -EACCES;
  }

  *memobj_out = &file->vnode->memobj;
  return 0;
}

void vfs_fork_fds(process_t* procA, process_t* procB) {
  if (ENABLE_KERNEL_SAFETY_NETS) {
    for (int i = 0; i < PROC_MAX_FDS; ++i) {
      KASSERT(procB->fds[i] == PROC_UNUSED_FD);
    }
  }

  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (procA->fds[i] != PROC_UNUSED_FD) {
      procB->fds[i] = procA->fds[i];
      g_file_table[procA->fds[i]]->refcount++;
    }
  }
}

// TODO(aoates): add a unit test for this.
int vfs_isatty(int fd) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_CHARDEV &&
      major(file->vnode->dev) == DEVICE_MAJOR_TTY) {
    return 1;
  } else {
    return 0;
  }
}

static int vfs_stat_internal(vnode_t* vnode, apos_stat_t* stat) {
  stat->st_dev = vnode->dev;
  stat->st_ino = vnode->num;
  stat->st_mode = 0;
  switch (vnode->type) {
    case VNODE_REGULAR: stat->st_mode |= VFS_S_IFREG; break;
    case VNODE_DIRECTORY: stat->st_mode |= VFS_S_IFDIR; break;
    case VNODE_BLOCKDEV: stat->st_mode |= VFS_S_IFBLK; break;
    case VNODE_CHARDEV: stat->st_mode |= VFS_S_IFCHR; break;
    case VNODE_SYMLINK: stat->st_mode |= VFS_S_IFLNK; break;
    case VNODE_FIFO: stat->st_mode |= VFS_S_IFIFO; break;

    case VNODE_INVALID:
    case VNODE_UNINITIALIZED:
      break;
  }
  if (stat->st_mode == 0)
    die("Invalid vnode type seen in vfs_lstat");

  stat->st_mode |= vnode->mode;
  stat->st_uid = vnode->uid;
  stat->st_gid = vnode->gid;
  stat->st_rdev = vnode->dev;
  stat->st_size = vnode->len;
  // TODO: stat->st_nlink
  if (vnode->fs->stat) {
    return vnode->fs->stat(vnode, stat);
  } else {
    return -ENOTSUP;
  }
}

static int vfs_path_stat_internal(const char* path, apos_stat_t* stat,
                                  int resolve_final_symlink) {
  if (!path || !stat) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(resolve_final_symlink),
                                    0x0, &child);
  if (result) return result;

  result = vfs_stat_internal(child, stat);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_stat(const char* path, apos_stat_t* stat) {
  return vfs_path_stat_internal(path, stat, 1);
}

int vfs_lstat(const char* path, apos_stat_t* stat) {
  return vfs_path_stat_internal(path, stat, 0);
}

int vfs_fstat(int fd, apos_stat_t* stat) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  file->refcount++;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_stat_internal(file->vnode, stat);
  }

  file->refcount--;
  return result;
}

static int vfs_chown_internal(vnode_t* vnode, uid_t owner, gid_t group) {
  if (owner < -1 || group < -1) return -EINVAL;

  if (!proc_is_superuser(proc_current())) {
    if (owner != -1 && owner != geteuid()) return -EPERM;
    if (vnode->uid != geteuid()) return -EPERM;
    // TODO(aoates): check group against supplementary group ids as well.
    if (group != -1 && group != getegid()) return -EPERM;
  }

  if (owner >= 0) vnode->uid = owner;
  if (group >= 0) vnode->gid = group;

  return 0;
}

static int vfs_chown_path_internal(const char* path, uid_t owner, gid_t group,
                                   int resolve_final_symlink) {
  if (!path || owner < -1 || group < -1) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(resolve_final_symlink),
                                    0x0, &child);
  if (result) return result;

  result = vfs_chown_internal(child, owner, group);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_chown(const char* path, uid_t owner, gid_t group) {
  return vfs_chown_path_internal(path, owner, group, 1);
}

int vfs_lchown(const char* path, uid_t owner, gid_t group) {
  return vfs_chown_path_internal(path, owner, group, 0);
}

int vfs_fchown(int fd, uid_t owner, gid_t group) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  file->refcount++;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_chown_internal(file->vnode, owner, group);
  }

  file->refcount--;
  return result;
}

static int vfs_chmod_internal(vnode_t* vnode, mode_t mode) {
  if (!is_valid_create_mode(mode)) return -EINVAL;

  if (!proc_is_superuser(proc_current()) &&
      vnode->uid != geteuid()) {
    return -EPERM;
  }

  vnode->mode = mode;
  return 0;
}

int vfs_chmod(const char* path, mode_t mode) {
  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(true), 0x0, &child);
  if (result) return result;

  result = vfs_chmod_internal(child, mode);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_fchmod(int fd, mode_t mode) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  file->refcount++;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_chmod_internal(file->vnode, mode);
  }

  file->refcount--;
  return result;
}

int vfs_symlink(const char* path1, const char* path2) {
  if (!path1 || !path2) {
    return -EINVAL;
  }

  vnode_t* root = get_root_for_path(path2);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path2, lookup_opt(false), &parent, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EEXIST;  // Root directory!
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  if (!parent->fs->symlink) {
    VFS_PUT_AND_CLEAR(parent);
    return -EPERM;
  }

  error = parent->fs->symlink(parent, base_name, path1);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_readlink(const char* path, char* buf, int bufsize) {
  if (!path || !buf || bufsize <= 0) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(false), 0x0, &child);
  if (result) return result;

  if (child->type != VNODE_SYMLINK) {
    VFS_PUT_AND_CLEAR(child);
    return -EINVAL;
  }

  if (!child->fs->readlink) {
    VFS_PUT_AND_CLEAR(child);
    return -EPERM;
  }

  result = child->fs->readlink(child, buf, bufsize);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_access(const char* path, int amode) {
  if (!path) return -EINVAL;
  if (amode == 0 ||
      (amode & ~(F_OK | R_OK | W_OK | X_OK)) != 0) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  lookup_options_t opt = lookup_opt(true);
  opt.check_real_ugid = true;
  int result = lookup_existing_path(path, opt, 0x0, &child);
  if (result) return result;

  result = 0;
  if (!result && (amode & R_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_READ, proc_current(), child);
  }
  if (!result && (amode & W_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_WRITE, proc_current(), child);
  }
  if (!result && (amode & X_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_EXEC, proc_current(), child);
  }
  if (!result && (amode & X_OK)) {
    // TODO(aoates): should we assume that the VFS_OP_EXEC check is sufficient?
    result = vfs_check_mode_rugid(VFS_OP_SEARCH, proc_current(), child);
  }

  VFS_PUT_AND_CLEAR(child);
  return result;
}

static bool is_truncate_type(const vnode_t* vnode) {
  return vnode->type == VNODE_REGULAR || vnode->type == VNODE_CHARDEV ||
         vnode->type == VNODE_FIFO;
}

int vfs_ftruncate(int fd, off_t length) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (!is_truncate_type(file->vnode)) {
    return -EINVAL;
  }
  if (file->mode != VFS_O_WRONLY && file->mode != VFS_O_RDWR) {
    return -EBADF;
  }
  if (length < 0) {
    return -EINVAL;
  }
  if (file->vnode->type == VNODE_CHARDEV || file->vnode->type == VNODE_FIFO) {
    return 0;
  }

  file->refcount++;

  KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
  result = file->vnode->fs->truncate(file->vnode, length);
  file->refcount--;
  return result;
}

int vfs_truncate(const char* path, off_t length) {
  if (!path || length < 0) {
    return -EINVAL;
  }

  vnode_t* vnode = 0x0;
  int result = lookup_existing_path(path, lookup_opt(true), 0x0, &vnode);
  if (result) return result;

  if (vnode->type == VNODE_DIRECTORY) result = -EISDIR;
  if (result == 0 && !is_truncate_type(vnode)) result = -EINVAL;
  if (result == 0)
    result = vfs_check_mode(VFS_OP_WRITE, proc_current(), vnode);
  if (result) {
    VFS_PUT_AND_CLEAR(vnode);
    return result;
  }

  if (vnode->type == VNODE_CHARDEV || vnode->type == VNODE_FIFO) {
    VFS_PUT_AND_CLEAR(vnode);
    return 0;
  }

  {
    KMUTEX_AUTO_LOCK(node_lock, &vnode->mutex);
    result = vnode->fs->truncate(vnode, length);
  }

  VFS_PUT_AND_CLEAR(vnode);
  return result;
}
