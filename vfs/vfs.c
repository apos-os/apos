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
#include "common/math.h"
#include "dev/dev.h"
#include "dev/tty.h"
#include "memory/kmalloc.h"
#include "memory/memobj_vnode.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
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

void vfs_vnode_init(vnode_t* n, fs_t* fs, int num) {
  n->fs = fs;
  n->fs_link = LIST_LINK_INIT;
  n->fstype[0] = 0x0;
  n->num = num;
  n->type = VNODE_UNINITIALIZED;
  n->state = VNODE_ST_WTF;
  n->len = -1;
  n->uid = -1;
  n->mode = 0;
  n->mounted_fs = VFS_FSID_NONE;
  n->parent_mount_point = 0x0;
  n->gid = -1;
  n->refcount = 0;
  kmutex_init(&n->mutex);
  kmutex_init(&n->state_mu);
  memobj_init_vnode(n);
}

void vfs_fs_init(fs_t* fs) {
  kmemset(fs, 0, sizeof(fs_t));
  fs->id = VFS_FSID_NONE;
  fs->open_vnodes = 0;
  fs->open_vnodes_list = LIST_INIT;
  fs->dev = kmakedev(DEVICE_ID_UNKNOWN, DEVICE_ID_UNKNOWN);
  kmutex_init(&fs->rename_lock);
}

#define VNODE_CACHE_SIZE 1000

// Return the index of the next free entry in the file table, or -1 if there's
// no space left.
//
// TODO(aoates): this could be much more efficient.
static int next_free_file_idx(void) {
  if (vfs_get_force_no_files()) return -1;
  for (int i = 0; i < VFS_MAX_FILES; ++i) {
    if (g_file_table[i] == 0x0) {
      return i;
    }
  }
  return -1;
}

// Return the lowest free fd in the process.
static int next_free_fd(process_t* p) {
  int max_fd = PROC_MAX_FDS;
  if (p->limits[APOS_RLIMIT_NOFILE].rlim_cur != APOS_RLIM_INFINITY)
    max_fd = min((apos_rlim_t)max_fd, p->limits[APOS_RLIMIT_NOFILE].rlim_cur);
  for (int i = 0; i < max_fd; ++i) {
    if (p->fds[i].file == PROC_UNUSED_FD) {
      return i;
    }
  }
  return -EMFILE;
}

// Returns non-zero if the given mode is a valid create mode_t (i.e. can be
// passed to chmod() or as the mode argument to open()).
static int is_valid_create_mode(kmode_t mode) {
  return (mode & ~(VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO | VFS_S_ISUID |
                   VFS_S_ISGID | VFS_S_ISVTX | VFS_S_IFMT)) == 0;
}

static void init_fifo_vnode(vnode_t* vnode) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);
  KASSERT_DBG(vnode->refcount >= 1);

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

static void cleanup_socket_vnode(vnode_t* vnode) {
  KASSERT_DBG(vnode->type == VNODE_SOCKET);
  KASSERT_DBG(vnode->refcount == 0);

  if (vnode->socket) {
    net_socket_destroy(vnode->socket);
    vnode->socket = NULL;
  }
  // If a socket is bound to this address, it should have a reference on the
  // vnode (and therefore we shouldn't be cleaning it up).
  KASSERT(vnode->bound_socket == NULL);
}

void vfs_init(void) {
  KASSERT(g_fs_table[VFS_ROOT_FS].fs == 0x0);
  kmutex_init(&g_fs_table_lock);

#if ENABLE_EXT2
  // First try to mount every block device as an ext2 fs.
  fs_t* ext2fs = ext2_create_fs();
  int success = 0;
  for (int bd_major = 0; bd_major <= DEVICE_MAX_MAJOR; ++bd_major) {
    for (int bd_minor = 0; bd_minor <= DEVICE_MAX_MINOR; ++bd_minor) {
      const apos_dev_t dev = kmakedev(bd_major, bd_minor);
      if (dev_get_block(dev)) {
        const int result = ext2_mount(ext2fs, dev);
        if (result == 0) {
          KLOG(INFO, "Found ext2 FS on device %d.%d\n", kmajor(dev),
               kminor(dev));
          g_fs_table[VFS_ROOT_FS].fs = ext2fs;
          success = 1;
          break;
        }
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

  // Create the anonymous socket filesystem.
  g_fs_table[VFS_SOCKET_FS].mount_point = NULL;
  g_fs_table[VFS_SOCKET_FS].mounted_root = NULL;
  g_fs_table[VFS_SOCKET_FS].fs = anonfs_create(VNODE_SOCKET);
  g_fs_table[VFS_SOCKET_FS].fs->id = VFS_SOCKET_FS;

  htbl_init(&g_vnode_cache, VNODE_CACHE_SIZE);

  for (int i = 0; i < VFS_MAX_FILES; ++i) {
    g_file_table[i] = 0x0;
  }

  KASSERT(proc_current()->cwd == 0x0);
  proc_current()->cwd = vfs_get_root_vnode();
}

fs_t* vfs_get_root_fs(void) {
  return g_fs_table[VFS_ROOT_FS].fs;
}

vnode_t* vfs_get_root_vnode(void) {
  fs_t* root_fs = vfs_get_root_fs();
  return vfs_get(root_fs, root_fs->get_root(root_fs));
}

// As vfs_get(), but the returned vnode *may* not be fully initialized.  This
// operation binds a particular (fs, vnode_num) tuple to a particular identity
// by creating a vnode_t object and putting it in the vnode table.
//
// The only operations that are valid on an uninitialized vnode are,
//  - comparing its pointer identity to another vnode
//  - reading its vnode number
//  - initializing it
//  - manipulating its refcount with vfs_ref() or vfs_put()
static vnode_t* vfs_get_uninitialized(fs_t* fs, int vnode_num) {
  vnode_t* vnode;
  kspin_lock(&g_vnode_cache_lock);
  int error = htbl_get(&g_vnode_cache, vnode_hash(fs, vnode_num),
                       (void**)(&vnode));
  if (!error) {
    KASSERT(vnode->num == vnode_num);
    KASSERT(vnode->refcount > 0);

    // Increment the refcount, then return the (possibly uninitialized!) vnode.
    vnode->refcount++;
    kspin_unlock(&g_vnode_cache_lock);

    return vnode;
  } else {
    // We need to create the vnode.
    vnode = fs->alloc_vnode(fs);
    vfs_vnode_init(vnode, fs, vnode_num);
    vnode->refcount = 1;
    vnode->state = VNODE_ST_BOUND;
    fs->open_vnodes++;
    list_push(&fs->open_vnodes_list, &vnode->fs_link);

    // Put the unitialized vnode into the table.
    htbl_put(&g_vnode_cache, vnode_hash_n(vnode), (void*)vnode);
    kspin_unlock(&g_vnode_cache_lock);

    // This is all we can do right now, without being able to take the vnode's
    // mutex.
    return vnode;
  }
}

// Force a vnode_t to be fully initialized if it is not already.  There are
// three outcomes:
//  1) success --- the vnode is now valid, pointer is unmodified.  Returns 0.
//     May block.
//  2) transient failure --- another thread put() the vnode simultaneously, and
//     we can't determine if it's valid or not.  Returns 0 and clears the vnode
//     pointer.  Call get and init again to find out.
//  3) error --- returns the error, vnode is pointer is cleared.
static int vfs_vnode_finish_init(vnode_t** n_ptr) {
  vnode_t* vnode = *n_ptr;
  KASSERT_DBG(vnode->refcount >= 1);

  kmutex_lock(&vnode->state_mu);
  if (vnode->state == VNODE_ST_VALID) {
    // Easy (and usual) case.  We're done.
    kmutex_unlock(&vnode->state_mu);
    return 0;
  } else if (vnode->state == VNODE_ST_BOUND) {
    KASSERT_DBG(vnode->type == VNODE_UNINITIALIZED);
    // The node needs to be initialized.  We won the lock, so we get to do it.
    // This call could block, at which point other threads attempting to
    // acquire/initialize this node will block until we release the mutex.
    int error = vnode->fs->get_vnode(vnode);

    if (error) {
      // In case the fs overwrote this.  We must do this before we unlock.
      vnode->type = VNODE_UNINITIALIZED;
      // TODO(aoates): consider signalling the error back to other callers via
      // the vnode object (whether here, or in vfs_put()).
      vnode->state = VNODE_ST_LAMED;
      KLOG(WARNING, "error when getting inode %d: %s\n",
           vnode->num, errorname(-error));

      // TODO(aoates): it's sorta gross that we do the htbl_remove in two spots
      // (here and in vfs_put, when node is transitioned to VNODE_ST_LAMED).  Is
      // there a nice way to unify those flows?
      // Remove lamed node from table.  Other threads are now free to attempt to
      // get+init it again; anyone who was waiting for us to finish this call
      // will vfs_put() as well, and one of us will clean up the vnode object.
      kspin_lock(&g_vnode_cache_lock);
      KASSERT(0 == htbl_remove(&g_vnode_cache, vnode_hash_n(vnode)));
      kspin_unlock(&g_vnode_cache_lock);

      kmutex_unlock(&vnode->state_mu);
      vfs_put(vnode);
      *n_ptr = NULL;
      return error;
    }

    if (vnode->type == VNODE_FIFO)
      init_fifo_vnode(vnode);
    vnode->socket = NULL;
    vnode->bound_socket = NULL;

    vnode->state = VNODE_ST_VALID;
    kmutex_unlock(&vnode->state_mu);
    return 0;
  } else if (vnode->state == VNODE_ST_LAMED) {
    // Another thread has put() the vnode.  It is invalid and no longer in the
    // table, but we still have a ref.
    if (ENABLE_KERNEL_SAFETY_NETS) {
      kspin_lock(&g_vnode_cache_lock);
      // Sanity check: this vnode should not be in the table (a new, non-LAMED
      // version may be, however).
      void* val;
      if (htbl_get(&g_vnode_cache, vnode_hash(vnode->fs, vnode->num), &val) ==
          0) {
        KASSERT(val != vnode);
      }
      kspin_unlock(&g_vnode_cache_lock);
    }
    kmutex_unlock(&vnode->state_mu);
    vfs_put(vnode);
    *n_ptr = NULL;
    return 0;  // Caller should try again.
  } else {
    KLOG(FATAL, "unexpected vnode state %d on inode %d\n", vnode->state,
         vnode->num);
    return -EINVAL;  // Unreachable.
  }
}

vnode_t* vfs_get(fs_t* fs, int vnode_num) {
  vnode_t* vnode = NULL;
  while (vnode == NULL) {
    vnode = vfs_get_uninitialized(fs, vnode_num);
    int result = vfs_vnode_finish_init(&vnode);
    if (result) {
      return NULL;  // Error already logged in vfs_vnode_finish_init().
    }
    // if vnode is NULL now, there was a put() race so we want to simply retry.
  }
  return vnode;
}

void vfs_ref(vnode_t* n) {
  // TODO(aoates): use atomic for refcount.
  kspin_lock(&g_vnode_cache_lock);
  n->refcount++;
  kspin_unlock(&g_vnode_cache_lock);
}

void vfs_put(vnode_t* vnode) {
  // TODO(aoates): consider a fast path where we just manipulate the refcount
  // without needing to take any locks.
  kmutex_lock(&vnode->state_mu);

  kspin_lock(&g_vnode_cache_lock);
  KASSERT_DBG(vnode->memobj.refcount >= 1);
  if (vnode->refcount > 1) {
    // We're definitely not the last.  Nothing else matters --- this vnode is
    // someone else's problem.
    vnode->refcount--;
    kspin_unlock(&g_vnode_cache_lock);
    kmutex_unlock(&vnode->state_mu);
    // vnode may now be invalid.
    return;
  }

  // We are currently holding the last reference, so we're responsible for
  // transitioning the vnode to the next state if needed.
  KASSERT(vnode->type != VNODE_INVALID);
  KASSERT(vnode->state == VNODE_ST_BOUND || vnode->state == VNODE_ST_VALID ||
          vnode->state == VNODE_ST_LAMED);

  if (vnode->state == VNODE_ST_VALID) {
    // The hard case.  vnode is valid and must be flushed/put.  Other threads
    // may acquire this vnode via the table, but they can't finish initializing
    // until we release state_mu.
    // TODO(aoates): instead of greedily freeing the vnode, mark it as
    // unnecessary and only free it later, if we need to.
    KASSERT(!kmutex_is_locked(&vnode->mutex));
    KASSERT(vnode->memobj.refcount == 1);
    kspin_unlock(&g_vnode_cache_lock);

    // TODO(aoates): look at return code from put_vnode() and do something if it
    // fails.
    vnode->fs->put_vnode(vnode);  // May block or call back into VFS.
    vnode->state = VNODE_ST_LAMED;

    // We've finished flushing, so another thread is free to get() a new copy of
    // this vnode.  Remove it from the table.
    kspin_lock(&g_vnode_cache_lock);

    // Note that other threads may have gotten this vnode from the table while
    // we were blocked in fs->put_vnode().
    KASSERT_DBG(vnode->refcount >= 1);
    KASSERT(0 == htbl_remove(&g_vnode_cache, vnode_hash_n(vnode)));
    // At this point it's guaranteed that no one new can get to the vnode.

    if (vnode->refcount > 1) {
      // Someone else came along while we were put()ing and tried to get the
      // node.  Let them clean it up.
      vnode->refcount--;
      kspin_unlock(&g_vnode_cache_lock);
      kmutex_unlock(&vnode->state_mu);
      // vnode may now be invalid.
      return;
    }
    // ...otherwise fall through and clean up ourselves.
  }

  // We're now in a terminal and non-blocking state (either found this way, or
  // because we just put the vnode and moved it to VNODE_ST_LAMED).
  // We're terminal AND holding the last reference.  Truly the end of the line.
  // Note: if we ever expose the get/init split externally, will need to handle
  // BOUND here as well (and remove from vnode table).
  KASSERT(vnode->state == VNODE_ST_LAMED);
  KASSERT(vnode->refcount == 1);

  // TODO(aoates): lock for fs data.
  vnode->fs->open_vnodes--;
  KASSERT_DBG(list_link_on_list(&vnode->fs->open_vnodes_list, &vnode->fs_link));
  list_remove(&vnode->fs->open_vnodes_list, &vnode->fs_link);
  KASSERT_DBG(vnode->fs->open_vnodes >= 0);
  kspin_unlock(&g_vnode_cache_lock);
  kmutex_unlock(&vnode->state_mu);
  vnode->refcount--;
  if (vnode->type == VNODE_FIFO) cleanup_fifo_vnode(vnode);
  if (vnode->type == VNODE_SOCKET) cleanup_socket_vnode(vnode);

  vnode->type = VNODE_INVALID;
  kfree(vnode);
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
static void vfs_set_created_metadata(vnode_t* vnode, kmode_t mode) {
  vnode->uid = geteuid();
  vnode->gid = getegid();
  vnode->mode = (mode & ~proc_current()->umask) & ~VFS_S_IFMT;
}

static int vfs_open_fifo(vnode_t* vnode, kmode_t mode, bool block) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);

  fifo_mode_t fifo_mode;
  if (mode == VFS_O_RDONLY) fifo_mode = FIFO_READ;
  else if (mode == VFS_O_WRONLY) fifo_mode = FIFO_WRITE;
  else return -EINVAL;

  return fifo_open(vnode->fifo, fifo_mode, block, false /* force */);
}

static void vfs_close_fifo(vnode_t* vnode, kmode_t mode) {
  KASSERT_DBG(vnode->type == VNODE_FIFO);

  fifo_mode_t fifo_mode;
  if (mode == VFS_O_RDONLY) fifo_mode = FIFO_READ;
  else if (mode == VFS_O_WRONLY) fifo_mode = FIFO_WRITE;
  else die("invalid mode seen in vfs_close_fifo");

  fifo_close(vnode->fifo, fifo_mode);
}

// TODO(aoates): move these to vfs_internal.c (requires moving some helpers).
void file_ref(file_t* file) {
  KASSERT(file->refcount >= 0);
  KASSERT(file->index >= 0);
  KASSERT(file->index < VFS_MAX_FILES);
  KASSERT(g_file_table[file->index] == file);
  file->refcount++;
}

void file_unref(file_t* file) {
  KASSERT(file->refcount >= 1);
  KASSERT(file->index >= 0);
  KASSERT(file->index < VFS_MAX_FILES);
  KASSERT(g_file_table[file->index] == file);

  file->refcount--;
  if (file->refcount == 0) {
    if (file->vnode->type == VNODE_FIFO)
      vfs_close_fifo(file->vnode, file->mode);

    // TODO(aoates): is there a race here? Does vfs_put block?  Could another
    // thread reference this fd/file during that time?  Maybe we need to remove
    // it from the table, and mark the GD as PROC_UNUSED_FD first?
    g_file_table[file->index] = 0x0;
    VFS_PUT_AND_CLEAR(file->vnode);
    file_free(file);
  }
}

int vfs_open_vnode(vnode_t* child, int flags, bool block) {
  const kmode_t mode = flags & VFS_MODE_MASK;
  if (child->type != VNODE_REGULAR && child->type != VNODE_DIRECTORY &&
      child->type != VNODE_CHARDEV && child->type != VNODE_BLOCKDEV &&
      child->type != VNODE_FIFO && child->type != VNODE_SOCKET) {
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

  if (child->type == VNODE_CHARDEV && kmajor(child->dev) == DEVICE_MAJOR_TTY &&
      !(flags & VFS_O_NOCTTY)) {
    tty_t* tty = tty_get(child->dev);
    if (!tty) {
      KLOG(DFATAL, "tty_get() failed in vnode open\n");
      return -EIO;
    }
    const ksid_t sid = proc_getsid(0);
    proc_session_t* const session = proc_session_get(sid);
    if (sid == proc_current()->id &&
        session->ctty == PROC_SESSION_NO_CTTY && tty->session < 0) {
      KLOG(DEBUG, "allocating TTY %d as controlling terminal for session %d\n",
           kminor(child->dev), sid);
      session->ctty = kminor(child->dev);
      tty->session = sid;
    }
  }

  // Allocate a new file_t in the global file table.
  int idx = next_free_file_idx();
  if (idx < 0) {
    if (child->type == VNODE_FIFO) vfs_close_fifo(child, mode);
    return -ENFILE;
  }

  process_t* proc = proc_current();
  int fd = next_free_fd(proc);
  if (fd < 0) {
    if (child->type == VNODE_FIFO) vfs_close_fifo(child, mode);
    return fd;
  }

  KASSERT(g_file_table[idx] == 0x0);
  g_file_table[idx] = file_alloc();
  g_file_table[idx]->index = idx;
  g_file_table[idx]->vnode = VFS_COPY_REF(child);
  g_file_table[idx]->refcount = 1;
  g_file_table[idx]->mode = mode;
  g_file_table[idx]->flags = flags;

  KASSERT(proc->fds[fd].file == PROC_UNUSED_FD);
  proc->fds[fd].file = idx;
  proc->fds[fd].flags = 0;

  if (flags & VFS_O_CLOEXEC) {
    proc->fds[fd].flags |= VFS_O_CLOEXEC;
  }

  return fd;
}

int vfs_open(const char* path, int flags, ...) {
  // Check arguments.
  const kmode_t mode = flags & VFS_MODE_MASK;
  if (mode != VFS_O_RDONLY && mode != VFS_O_WRONLY && mode != VFS_O_RDWR) {
    return -EINVAL;
  }
  kmode_t create_mode = 0;
  if (flags & VFS_O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, kmode_t);
    va_end(args);
  }

  if (!is_valid_create_mode(create_mode)) return -EINVAL;
  if (mode == VFS_O_RDONLY && (flags & VFS_O_TRUNC)) return -EACCES;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0, *child = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  bool follow_final_symlink =
      !((flags & VFS_O_CREAT) && (flags & VFS_O_EXCL)) &&
      !(flags & VFS_O_NOFOLLOW);
  lookup_options_t lookup = lookup_opt(follow_final_symlink);
  lookup.lock_on_noent = true;
  int error = lookup_path(root, path, lookup, &parent, &child, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  int created = 0;
  if (child == NULL) {
    if (!(flags & VFS_O_CREAT)) {
      kmutex_unlock(&parent->mutex);
      VFS_PUT_AND_CLEAR(parent);
      return -ENOENT;
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
        parent->fs->mknod(parent, base_name, VNODE_REGULAR, kmakedev(0, 0));
    if (child_inode < 0) {
      kmutex_unlock(&parent->mutex);
      VFS_PUT_AND_CLEAR(parent);
      return child_inode;
    }

    child = vfs_get(parent->fs, child_inode);
    vfs_set_created_metadata(child, create_mode);
    created = 1;
    kmutex_unlock(&parent->mutex);  // Locked because of lock_on_noent.
  } else if ((flags & VFS_O_CREAT) && (flags & VFS_O_EXCL)) {
    VFS_PUT_AND_CLEAR(parent);
    VFS_PUT_AND_CLEAR(child);
    return -EEXIST;
  }

  // Done with the parent.
  VFS_PUT_AND_CLEAR(parent);

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

  if (child->type == VNODE_SOCKET) {
    VFS_PUT_AND_CLEAR(child);
    return -EOPNOTSUPP;
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
  if (fd < 0 || fd >= PROC_MAX_FDS || proc->fds[fd].file == PROC_UNUSED_FD) {
    return -EBADF;
  }
  KASSERT_DBG(proc->fds[fd].flags == 0 || proc->fds[fd].flags == VFS_O_CLOEXEC);

  file_t* file = g_file_table[proc->fds[fd].file];
  KASSERT(file != 0x0);
  proc->fds[fd].file = PROC_UNUSED_FD;
  file_unref(file);
  return 0;
}

int vfs_dup(int orig_fd) {
  file_t* file = 0x0;
  int result = lookup_fd(orig_fd, &file);
  if (result) return result;

  process_t* proc = proc_current();
  int new_fd = next_free_fd(proc);
  if (new_fd < 0) {
    file_unref(file);
    return new_fd;
  }

  KASSERT_DBG(proc->fds[new_fd].file == PROC_UNUSED_FD);
  proc->fds[new_fd] = proc->fds[orig_fd];  // Transfer our ref on |file|.
  return new_fd;
}

int vfs_dup2(int fd1, int fd2) {
  file_t* file1 = 0x0, *file2 = 0x0;

  if (!is_valid_fd(fd2)) return -EBADF;
  if (proc_current()->limits[APOS_RLIMIT_NOFILE].rlim_cur !=
          APOS_RLIM_INFINITY &&
      (apos_rlim_t)fd2 >= proc_current()->limits[APOS_RLIMIT_NOFILE].rlim_cur)
    return -EMFILE;

  int result = lookup_fd(fd1, &file1);
  if (result) return result;

  if (fd1 == fd2) {
    file_unref(file1);
    return fd2;
  }

  // Close fd2 if it already exists.
  result = lookup_fd(fd2, &file2);
  if (result == 0) {
    file_unref(file2);
    result = vfs_close(fd2);
    if (result) {
      file_unref(file1);
      return result;
    }
  }

  process_t* proc = proc_current();

  KASSERT_DBG(proc->fds[fd2].file == PROC_UNUSED_FD);
  proc->fds[fd2] = proc->fds[fd1];  // Transfer our ref on |file1|.
  return fd2;
}

int vfs_mkdir(const char* path, kmode_t mode) {
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

  kmutex_lock(&parent->mutex);
  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  int child_inode = parent->fs->mkdir(parent, base_name);
  if (child_inode < 0) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;  // Error :(
  }

  vnode_t* child = vfs_get(parent->fs, child_inode);
  kmutex_unlock(&parent->mutex);
  vfs_set_created_metadata(child, mode);
  VFS_PUT_AND_CLEAR(child);

  // We're done!
  VFS_PUT_AND_CLEAR(parent);
  return 0;
}

static int vfs_mknod_internal(const char* path, kmode_t mode, apos_dev_t dev,
                              bool follow_final_symlink, vnode_t** vnode_out) {
  if (!is_valid_create_mode(mode)) return -EINVAL;

  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(follow_final_symlink), &parent,
                          0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    VFS_PUT_AND_CLEAR(parent);
    return -EEXIST;  // Root directory!
  }

  kmutex_lock(&parent->mutex);
  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  vnode_type_t type = VNODE_INVALID;
  if (VFS_S_ISREG(mode)) type = VNODE_REGULAR;
  else if (VFS_S_ISBLK(mode)) type = VNODE_BLOCKDEV;
  else if (VFS_S_ISCHR(mode)) type = VNODE_CHARDEV;
  else if (VFS_S_ISFIFO(mode)) type = VNODE_FIFO;
  else if (VFS_S_ISSOCK(mode)) type = VNODE_SOCKET;
  else die("unknown node type");

  int child_inode = parent->fs->mknod(parent, base_name, type, dev);
  if (child_inode < 0) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;  // Error :(
  }

  vnode_t* child = vfs_get(parent->fs, child_inode);
  kmutex_unlock(&parent->mutex);
  vfs_set_created_metadata(child, mode & ~VFS_S_IFMT);
  *vnode_out = child;

  // We're done!
  VFS_PUT_AND_CLEAR(parent);
  return 0;
}

int vfs_mknod(const char* path, kmode_t mode, apos_dev_t dev) {
  if (!VFS_S_ISREG(mode) && !VFS_S_ISCHR(mode) && !VFS_S_ISBLK(mode) &&
      !VFS_S_ISFIFO(mode)) {
    return -EINVAL;
  }
  vnode_t* node = NULL;
  int result = vfs_mknod_internal(path, mode, dev, false, &node);
  if (result == 0) {
    VFS_PUT_AND_CLEAR(node);
  }
  return result;
}

int vfs_mksocket(const char* path, kmode_t mode, vnode_t** vnode_out) {
  if (!VFS_S_ISSOCK(mode)) {
    return -EINVAL;
  }
  return vfs_mknod_internal(path, mode, 0, true, vnode_out);
}

int vfs_rmdir(const char* path) {
  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  vnode_t* child = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // Get the child so we can vfs_put() it after calling fs->unlink(), which will
  // collect the inode if it's now unused.
  lookup_options_t lookup = lookup_opt(false);
  lookup.resolve_final_mount = false;
  int error = lookup_existing_path_and_lock(root, path, lookup, &parent, &child,
                                            base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  if (base_name[0] == '\0') {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EPERM;  // Root directory!
  } else if (kstrcmp(base_name, ".") == 0) {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EINVAL;
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  if (child->mounted_fs != VFS_FSID_NONE) {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EBUSY;
  }

  error = parent->fs->rmdir(parent, base_name, child);
  vfs_unlock_vnodes(parent, child);
  // This actually collects the inode in the fs (if this is the last ref).
  VFS_PUT_AND_CLEAR(child);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

int vfs_link(const char* path1, const char* path2) {
  vnode_t* parent2 = 0x0;
  vnode_t* vnode1 = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_existing_path(path1, lookup_opt(false), &vnode1);
  if (error) {
    return error;
  }

  if (vnode1->type == VNODE_DIRECTORY) {
    VFS_PUT_AND_CLEAR(vnode1);
    return -EPERM;
  }

  vnode_t* root2 = get_root_for_path(path2);
  error =
      lookup_path(root2, path2, lookup_opt(false), &parent2, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root2);
  if (error) {
    VFS_PUT_AND_CLEAR(vnode1);
    return error;
  }

  if (vnode1->fs != parent2->fs) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent2);
    return -EXDEV;
  }

  vfs_lock_vnodes(parent2, vnode1);
  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent2);
  if (mode_check) {
    vfs_unlock_vnodes(parent2, vnode1);
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent2);
    return mode_check;
  }

  error = parent2->fs->link(parent2, vnode1, base_name);
  vfs_unlock_vnodes(parent2, vnode1);
  VFS_PUT_AND_CLEAR(vnode1);
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

int vfs_rename(const char* path1, const char* path2) {
  int result = vfs_rename_unique(path1, path2);
  if (result == -ERENAMESAMEVNODE) result = 0;
  return result;
}

int vfs_rename_unique(const char* path1, const char* path2) {
  vnode_t* parent1 = 0x0, *parent2 = 0x0;
  vnode_t* vnode1 = 0x0, *vnode2 = 0x0;
  char base_name1[VFS_MAX_FILENAME_LENGTH];
  char base_name2[VFS_MAX_FILENAME_LENGTH];

  vnode_t* root1 = get_root_for_path(path1);
  lookup_options_t lookup = lookup_opt(false);
  lookup.resolve_final_mount = false;
  int error = lookup_path(root1, path1, lookup, &parent1, &vnode1,
                          base_name1);
  VFS_PUT_AND_CLEAR(root1);
  if (error == 0 && !vnode1) {
    VFS_PUT_AND_CLEAR(parent1);
    return -ENOENT;
  } else if (error) {
    return error;
  }

  vnode_t* root2 = get_root_for_path(path2);
  error = lookup_path(root2, path2, lookup, &parent2, &vnode2, base_name2);
  VFS_PUT_AND_CLEAR(root2);
  if (error) {
    VFS_PUT_AND_CLEAR(vnode1);
    VFS_PUT_AND_CLEAR(parent1);
    return error;
  }

  if (vnode1->fs != parent2->fs) {
    error = -EXDEV;
    goto done;
  }

  // Lock the rename lock to prevent topology changes.
  kmutex_lock(&vnode1->fs->rename_lock);

  if (vfs_check_mode(VFS_OP_WRITE, proc_current(), parent1) ||
      vfs_check_mode(VFS_OP_WRITE, proc_current(), parent2)) {
    error = -EACCES;
    goto done2;
  }

  if (kstrcmp(base_name1, ".") == 0 || kstrcmp(base_name1, "..") == 0 ||
      kstrcmp(base_name2, ".") == 0 || kstrcmp(base_name2, "..") == 0) {
    error = -EINVAL;
    goto done2;
  }

  if (vnode1->type == VNODE_DIRECTORY && vfs_is_ancestor(vnode1, parent2)) {
    error = -EINVAL;
    goto done2;
  }

  // Renaming to or from the root directory can never be useful --- it is
  // probably non-empty (in which case it can't be removed as a target).  If it
  // _is_ empty, it can only be moved onto itself, which is a no-op.  And it
  // can't ever be the source of a rename, because it is an ancestor of
  // everything.  Just reject it here to make logic below simpler.
  if (base_name1[0] == '\0' || base_name2[0] == '\0') {
    error = -EINVAL;
    goto done2;
  }

  // Now lock all four vnodes and stabilize the lookups.  See
  // lookup_existing_path_and_lock() for more comments on this approach.

  // This array will, after this point, always hold a set of up to 4 distinct
  // locked vnodes.
  vnode_t* vnodes_to_lock[4] = {parent1, vnode1, parent2, vnode2};
  vfs_lock_vnodes2(vnodes_to_lock, 4);

  const int kMaxRetries = 10;
  int attempts_left = kMaxRetries;
  while (--attempts_left > 0) {
    // N.B.(aoates): no need for resolving symlinks or mounts (up or down) ---
    // symlinks are operated on directly and both ".." (up) and mount points
    // (down) are rejected.

    // TODO(aoates): need to re-check search perms on the parent1 here.

    vnode_t *new_vnode1 = NULL, *new_vnode2 = NULL;
    int result = lookup_locked(parent1, base_name1, &new_vnode1);
    if (result < 0) {
      if (result != -ENOENT) {
        klogfm(KL_VFS, INFO,
               "vfs: child1 changed during rename lookup; lookup error: %s\n",
               errorname(-result));
      }
      error = result;
      goto done3;
    }

    result = lookup_locked(parent2, base_name2, &new_vnode2);
    if (result < 0 && result != -ENOENT) {
      klogfm(KL_VFS, INFO,
             "vfs: child2 changed during rename lookup; lookup error: %s\n",
             errorname(-result));
      error = result;
      VFS_PUT_AND_CLEAR(new_vnode1);
      goto done3;
    }

    if (new_vnode1 == vnode1 && new_vnode2 == vnode2) {
      // We're done!  Ditch second refs.
      VFS_PUT_AND_CLEAR(new_vnode1);
      if (new_vnode2) VFS_PUT_AND_CLEAR(new_vnode2);
      break;
    }

    // Binding changed.  Unlock, update children, relock, and try again.
    klogfm(KL_VFS, DEBUG,
           "vfs: child changed during rename lookup (fs=%d "
           "parent1=%d name1='%s' old_child1=%d new_child1=%d "
           "parent2=%d name2='%s' old_child2=%d new_child2=%d)\n",
           parent1->fs->id, parent1->num, base_name1, vnode1->num,
           new_vnode1->num, parent2->num, base_name2,
           (vnode2 ? vnode2->num : -1), (new_vnode2 ? new_vnode2->num : -1));
    vfs_unlock_vnodes2(vnodes_to_lock, 4);
    VFS_PUT_AND_CLEAR(vnode1);
    if (vnode2) VFS_PUT_AND_CLEAR(vnode2);
    vnode1 = VFS_MOVE_REF(new_vnode1);
    vnode2 = VFS_MOVE_REF(new_vnode2);
    vnodes_to_lock[0] = parent1; vnodes_to_lock[1] = vnode1;
    vnodes_to_lock[2] = parent2; vnodes_to_lock[3] = vnode2;
    vfs_lock_vnodes2(vnodes_to_lock, 4);
  }
  if (attempts_left <= 0) {
    klogfm(KL_VFS, WARNING,
           "vfs: unable to stabilize lookups for rename('%s', '%s')\n", path1,
           path2);
    error = -EIO;
    goto done3;
  }

  if ((path1[kstrlen(path1) - 1] == '/' && vnode1->type != VNODE_DIRECTORY) ||
      (path2[kstrlen(path2) - 1] == '/' &&
       ((!vnode2 && vnode1->type != VNODE_DIRECTORY) ||
        (vnode2 && vnode2->type != VNODE_DIRECTORY)))) {
    error = -ENOTDIR;
    goto done3;
  }

  KASSERT_DBG(vnode1->parent_mount_point == NULL);
  KASSERT_DBG(!vnode2 || vnode2->parent_mount_point == NULL);
  if (vnode1->mounted_fs != VFS_FSID_NONE ||
      (vnode2 && vnode2->mounted_fs != VFS_FSID_NONE)) {
    if (vnode2) VFS_PUT_AND_CLEAR(vnode2);
    error = -EBUSY;
    goto done3;
  }

  if (vnode2) {
    if (vnode1 == vnode2) {
      error = -ERENAMESAMEVNODE;
      goto done3;
    }

    if (vnode1->type != VNODE_DIRECTORY && vnode2->type == VNODE_DIRECTORY) {
      error = -EISDIR;
    } else if (vnode1->type == VNODE_DIRECTORY &&
               vnode2->type != VNODE_DIRECTORY) {
      error = -ENOTDIR;
    } else if (vnode2->type == VNODE_DIRECTORY) {
      error = parent2->fs->rmdir(parent2, base_name2, vnode2);
    } else {
      error = parent2->fs->unlink(parent2, base_name2, vnode2);
    }
    if (error) goto done3;
  }

  error = parent1->fs->unlink(parent1, base_name1, vnode1);
  if (error) goto done3;

  error = parent2->fs->link(parent2, vnode1, base_name2);

done3:
  vfs_unlock_vnodes2(vnodes_to_lock, 4);
done2:
  kmutex_unlock(&vnode1->fs->rename_lock);
done:
  VFS_PUT_AND_CLEAR(vnode1);
  if (vnode2) VFS_PUT_AND_CLEAR(vnode2);
  VFS_PUT_AND_CLEAR(parent1);
  VFS_PUT_AND_CLEAR(parent2);
  return error;
}

int vfs_unlink(const char* path) {
  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  vnode_t* child = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  // Get the child so we can vfs_put() it after calling fs->unlink(), which will
  // collect the inode if it's now unused.
  lookup_options_t lookup = lookup_opt(false);
  lookup.resolve_final_mount = false;
  int error = lookup_existing_path_and_lock(root, path, lookup, &parent, &child,
                                            base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  if (child->type == VNODE_DIRECTORY) {
    vfs_unlock_vnodes(parent, child);
    VFS_PUT_AND_CLEAR(child);
    VFS_PUT_AND_CLEAR(parent);
    return -EISDIR;
  }

  error = parent->fs->unlink(parent, base_name, child);
  vfs_unlock_vnodes(parent, child);
  // This actually collects the inode in the fs (if this is the last ref).
  VFS_PUT_AND_CLEAR(child);
  VFS_PUT_AND_CLEAR(parent);
  return error;
}

ssize_t vfs_read(int fd, void* buf, size_t count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    file_unref(file);
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR &&
             file->vnode->type != VNODE_CHARDEV &&
             file->vnode->type != VNODE_BLOCKDEV &&
             file->vnode->type != VNODE_FIFO &&
             file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_RDONLY && file->mode != VFS_O_RDWR) {
    file_unref(file);
    return -EBADF;
  }

  if (file->vnode->type == VNODE_FIFO) {
    result = fifo_read(file->vnode->fifo, buf, count,
                       !(file->flags & VFS_O_NONBLOCK));
  } else if (file->vnode->type == VNODE_SOCKET) {
    KASSERT(file->vnode->socket != NULL);
    result = file->vnode->socket->s_ops->recvfrom(
        file->vnode->socket, file->flags, buf, count, 0, NULL, 0);
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

  file_unref(file);
  return result;
}

ssize_t vfs_write(int fd, const void* buf, size_t count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    file_unref(file);
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR &&
             file->vnode->type != VNODE_CHARDEV &&
             file->vnode->type != VNODE_BLOCKDEV &&
             file->vnode->type != VNODE_FIFO &&
             file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_WRONLY && file->mode != VFS_O_RDWR) {
    file_unref(file);
    return -EBADF;
  }

  if (file->vnode->type == VNODE_FIFO) {
    result = fifo_write(file->vnode->fifo, buf, count,
                        !(file->flags & VFS_O_NONBLOCK));
  } else if (file->vnode->type == VNODE_SOCKET) {
    KASSERT(file->vnode->socket != NULL);
    result = file->vnode->socket->s_ops->sendto(
        file->vnode->socket, file->flags, buf, count, 0, NULL, 0);
  } else if (file->vnode->type == VNODE_CHARDEV) {
    result = special_device_write(file->vnode->type, file->vnode->dev,
                                  file->pos, buf, count, file->flags);
  } else {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    if (file->vnode->type == VNODE_REGULAR) {
      if (file->flags & VFS_O_APPEND) file->pos = file->vnode->len;
      const apos_rlim_t limit =
          proc_current()->limits[APOS_RLIMIT_FSIZE].rlim_cur;
      if (limit != APOS_RLIM_INFINITY) {
        koff_t new_len = max(file->vnode->len, file->pos + (koff_t)count);
        if (new_len > file->vnode->len && (apos_rlim_t)new_len > limit) {
          if ((apos_rlim_t)file->pos >= limit) {
            file_unref(file);
            proc_force_signal(proc_current(), SIGXFSZ);
            return -EFBIG;
          } else {
            count = limit - file->pos;
          }
        }
      }
      result = file->vnode->fs->write(file->vnode, file->pos, buf, count);
    } else {
      result = special_device_write(file->vnode->type, file->vnode->dev,
                                    file->pos, buf, count, file->flags);
    }
    if (result >= 0) {
      file->pos += result;
    }
  }

  file_unref(file);
  return result;
}

koff_t vfs_seek(int fd, koff_t offset, int whence) {
  if (whence != VFS_SEEK_SET && whence != VFS_SEEK_CUR &&
      whence != VFS_SEEK_END) {
    return -EINVAL;
  }

  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_FIFO) {
    file_unref(file);
    return -ESPIPE;
  }
  if (file->vnode->type != VNODE_REGULAR &&
      file->vnode->type != VNODE_CHARDEV &&
      file->vnode->type != VNODE_BLOCKDEV) {
    file_unref(file);
    return -ENOTSUP;
  }

  if (file->vnode->type == VNODE_CHARDEV) {
    KASSERT_DBG(file->pos == 0);
    file_unref(file);
    return 0;
  }

  int new_pos = -1;
  switch (whence) {
    case VFS_SEEK_SET: new_pos = offset; break;
    case VFS_SEEK_CUR: new_pos = file->pos + offset; break;
    case VFS_SEEK_END: new_pos = file->vnode->len + offset; break;
  }

  if (new_pos < 0) {
    file_unref(file);
    return -EINVAL;
  } else if (file->vnode->type == VNODE_BLOCKDEV) {
    // Verify that we're in bounds for the device.
    KASSERT(file->vnode->len == 0);
    block_dev_t* dev = dev_get_block(file->vnode->dev);
    if (!dev) {
      file_unref(file);
      return -ENXIO;
    }
    if (new_pos >= dev->sectors * dev->sector_size) {
      file_unref(file);
      return -EINVAL;
    }
  }

  file->pos = new_pos;
  file_unref(file);
  return file->pos;
}

int vfs_getdents(int fd, kdirent_t* buf, int count) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_DIRECTORY) {
    file_unref(file);
    return -ENOTDIR;
  }

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = file->vnode->fs->getdents(file->vnode, file->pos, buf, count);
    if (result > 0) {
      // Find the last returned dirent_t, and use it's offset.
      kdirent_t* ent = buf;
      int bufpos = 0;
      while (bufpos < result) {
        ent = (kdirent_t*)((char*)buf + bufpos);
        bufpos += ent->d_reclen;
      }
      file->pos = ent->d_offset;
    }
  }

  file_unref(file);
  return result;
}

int vfs_getcwd(char* path_out, size_t size) {
  // TODO(aoates): size_t all the way down.
  return vfs_get_vnode_dir_path(proc_current()->cwd, path_out, size);
}

int vfs_chdir(const char* path) {
  vnode_t* new_cwd = 0x0;
  int error = lookup_existing_path(path, lookup_opt(true), &new_cwd);
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

int vfs_get_memobj(int fd, kmode_t mode, memobj_t** memobj_out) {
  *memobj_out = 0x0;
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (file->vnode->type == VNODE_DIRECTORY) {
    file_unref(file);
    return -EISDIR;
  } else if (file->vnode->type != VNODE_REGULAR) {
    file_unref(file);
    return -ENOTSUP;
  }
  if (file->mode != VFS_O_RDWR && file->mode != mode) {
    file_unref(file);
    return -EACCES;
  }

  file->vnode->memobj.ops->ref(&file->vnode->memobj);
  *memobj_out = &file->vnode->memobj;
  file_unref(file);
  return 0;
}

void vfs_fork_fds(process_t* procA, process_t* procB) {
  if (ENABLE_KERNEL_SAFETY_NETS) {
    for (int i = 0; i < PROC_MAX_FDS; ++i) {
      KASSERT(procB->fds[i].file == PROC_UNUSED_FD);
    }
  }

  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (procA->fds[i].file != PROC_UNUSED_FD) {
      procB->fds[i] = procA->fds[i];
      file_ref(g_file_table[procA->fds[i].file]);
    }
  }
}

// TODO(aoates): add a unit test for this.
int vfs_isatty(int fd) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  result = 0;
  if (file->vnode->type == VNODE_CHARDEV &&
      kmajor(file->vnode->dev) == DEVICE_MAJOR_TTY) {
    result = 1;
  }
  file_unref(file);
  return result;
}

static int vfs_stat_internal(vnode_t* vnode, apos_stat_t* stat) {
  kmutex_assert_is_held(&vnode->mutex);
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
    case VNODE_SOCKET: stat->st_mode |= VFS_S_IFSOCK; break;
    case VNODE_INVALID:
    case VNODE_UNINITIALIZED:
    case VNODE_MAX:
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
  int result =
      lookup_existing_path(path, lookup_opt(resolve_final_symlink), &child);
  if (result) return result;

  kmutex_lock(&child->mutex);
  result = vfs_stat_internal(child, stat);
  kmutex_unlock(&child->mutex);
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

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_stat_internal(file->vnode, stat);
  }

  file_unref(file);
  return result;
}

static int vfs_chown_internal(vnode_t* vnode, kuid_t owner, kgid_t group) {
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

static int vfs_chown_path_internal(const char* path, kuid_t owner, kgid_t group,
                                   int resolve_final_symlink) {
  if (!path || owner < -1 || group < -1) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  int result =
      lookup_existing_path(path, lookup_opt(resolve_final_symlink), &child);
  if (result) return result;

  result = vfs_chown_internal(child, owner, group);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_chown(const char* path, kuid_t owner, kgid_t group) {
  return vfs_chown_path_internal(path, owner, group, 1);
}

int vfs_lchown(const char* path, kuid_t owner, kgid_t group) {
  return vfs_chown_path_internal(path, owner, group, 0);
}

int vfs_fchown(int fd, kuid_t owner, kgid_t group) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_chown_internal(file->vnode, owner, group);
  }

  file_unref(file);
  return result;
}

static int vfs_chmod_internal(vnode_t* vnode, kmode_t mode) {
  if (!is_valid_create_mode(mode)) return -EINVAL;

  if (!proc_is_superuser(proc_current()) &&
      vnode->uid != geteuid()) {
    return -EPERM;
  }

  vnode->mode = mode;
  return 0;
}

int vfs_chmod(const char* path, kmode_t mode) {
  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(true), &child);
  if (result) return result;

  result = vfs_chmod_internal(child, mode);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_fchmod(int fd, kmode_t mode) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  {
    KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
    result = vfs_chmod_internal(file->vnode, mode);
  }

  file_unref(file);
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

  kmutex_lock(&parent->mutex);
  int mode_check = vfs_check_mode(VFS_OP_WRITE, proc_current(), parent);
  if (mode_check) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return mode_check;
  }

  if (!parent->fs->symlink) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return -EPERM;
  }

  int child_inode = parent->fs->symlink(parent, base_name, path1);
  if (child_inode < 0) {
    kmutex_unlock(&parent->mutex);
    VFS_PUT_AND_CLEAR(parent);
    return child_inode;
  }

  vnode_t* child = vfs_get(parent->fs, child_inode);
  kmutex_unlock(&parent->mutex);
  vfs_set_created_metadata(child, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO);
  VFS_PUT_AND_CLEAR(parent);
  VFS_PUT_AND_CLEAR(child);

  return 0;
}

int vfs_readlink(const char* path, char* buf, size_t bufsize) {
  if (!path || !buf || bufsize == 0 || bufsize >= INT_MAX) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  int result = lookup_existing_path(path, lookup_opt(false), &child);
  if (result) return result;

  if (child->type != VNODE_SYMLINK) {
    VFS_PUT_AND_CLEAR(child);
    return -EINVAL;
  }

  if (!child->fs->readlink) {
    VFS_PUT_AND_CLEAR(child);
    return -EPERM;
  }

  kmutex_lock(&child->mutex);
  result = child->fs->readlink(child, buf, bufsize);
  kmutex_unlock(&child->mutex);
  VFS_PUT_AND_CLEAR(child);
  return result;
}

int vfs_access(const char* path, int amode) {
  if (!path) return -EINVAL;
  if (amode == 0 ||
      (amode & ~(VFS_F_OK | VFS_R_OK | VFS_W_OK | VFS_X_OK)) != 0) {
    return -EINVAL;
  }

  vnode_t* child = 0x0;
  lookup_options_t opt = lookup_opt(true);
  opt.check_real_ugid = true;
  int result = lookup_existing_path(path, opt, &child);
  if (result) return result;

  result = 0;
  if (!result && (amode & VFS_R_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_READ, proc_current(), child);
  }
  if (!result && (amode & VFS_W_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_WRITE, proc_current(), child);
  }
  if (!result && (amode & VFS_X_OK)) {
    result = vfs_check_mode_rugid(VFS_OP_EXEC, proc_current(), child);
  }
  if (!result && (amode & VFS_X_OK)) {
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

int vfs_ftruncate(int fd, koff_t length) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  if (result) return result;

  if (!is_truncate_type(file->vnode)) {
    file_unref(file);
    return -EINVAL;
  }
  if (file->mode != VFS_O_WRONLY && file->mode != VFS_O_RDWR) {
    file_unref(file);
    return -EBADF;
  }
  if (length < 0) {
    file_unref(file);
    return -EINVAL;
  }
  if (file->vnode->type == VNODE_CHARDEV || file->vnode->type == VNODE_FIFO) {
    file_unref(file);
    return 0;
  }
  const apos_rlim_t limit = proc_current()->limits[APOS_RLIMIT_FSIZE].rlim_cur;
  if (limit != APOS_RLIM_INFINITY && (apos_rlim_t)length > limit) {
    proc_force_signal(proc_current(), SIGXFSZ);
    file_unref(file);
    return -EFBIG;
  }

  KMUTEX_AUTO_LOCK(node_lock, &file->vnode->mutex);
  result = file->vnode->fs->truncate(file->vnode, length);
  file_unref(file);
  return result;
}

int vfs_truncate(const char* path, koff_t length) {
  if (!path || length < 0) {
    return -EINVAL;
  }

  vnode_t* vnode = 0x0;
  int result = lookup_existing_path(path, lookup_opt(true), &vnode);
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

  const apos_rlim_t limit = proc_current()->limits[APOS_RLIMIT_FSIZE].rlim_cur;
  if (limit != APOS_RLIM_INFINITY && (apos_rlim_t)length > limit) {
    VFS_PUT_AND_CLEAR(vnode);
    proc_force_signal(proc_current(), SIGXFSZ);
    return -EFBIG;
  }

  {
    KMUTEX_AUTO_LOCK(node_lock, &vnode->mutex);
    result = vnode->fs->truncate(vnode, length);
  }

  VFS_PUT_AND_CLEAR(vnode);
  return result;
}
