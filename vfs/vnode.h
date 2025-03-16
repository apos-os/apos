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

// vnode_t definition and associated constants and operations.
#ifndef APOO_VFS_VNODE_H
#define APOO_VFS_VNODE_H

#include "common/atomic.h"
#include "memory/memobj.h"
#include "net/socket/socket.h"
#include "proc/kmutex.h"
#include "user/include/apos/dev.h"
#include "user/include/apos/posix_types.h"
#include "user/include/apos/vfs/stat.h"
#include "vfs/fifo.h"
#include "vfs/fsid.h"

struct fs;
typedef struct fs fs_t;

// vnode types.  Keep these synchcronized with VNODE_TYPE_NAME.
typedef enum {
  VNODE_UNINITIALIZED = 0,
  VNODE_INVALID = 1,
  VNODE_REGULAR   = 2,
  VNODE_DIRECTORY = 3,
  VNODE_BLOCKDEV = 4,
  VNODE_CHARDEV = 5,
  VNODE_SYMLINK = 6,
  VNODE_FIFO = 7,
  VNODE_SOCKET = 8,
  VNODE_MAX,
} vnode_type_t;

static const char* const VNODE_TYPE_NAME[] = {
    "UNINIT", "INV", "REG", "DIR", "BLK", "CHR", "SYM", "FIFO", "SOCK",
};
_Static_assert(sizeof(VNODE_TYPE_NAME) / sizeof(const char*) == VNODE_MAX,
               "VNODE_TYPE_NAME doesn't match vnode_type_t");

// Internal state of the vnode.  Outside of vfs_get(), vfs_put(), and friends,
// clients should mostly only deal with VALID vnodes, or occasionally BOUND.
// There are two additional "implicit" states: INITIALIZING (between BOUND and
// VALID) and PUTTING (between VALID and LAMED).  If the vnode is in one of
// those states, state_mu will be held until the transition is complete.
typedef enum {
  // Sentinel state that should never be observed.
  VNODE_ST_WTF = 0,

  // The vnode has been bound to a particular (fs, inode) tuple in the global
  // table.  It is not initialized, however, and may not be valid or actually
  // exist in the underlying filesystem.
  VNODE_ST_BOUND = 1,

  // The vnode is bound and valid.  Have fun.
  VNODE_ST_VALID = 2,

  // The vnode has been put() and should no longer be considered valid.  The
  // only thing that can be done is examine the error field (if applicable) and
  // put your reference.
  VNODE_ST_LAMED = 3,
} vnode_state_t;

// A virtual node in the filesystem.  It is expected that concete filesystems
// will embed the vnode_t structure in their own, custom structure with
// additional metadata.
//
// const after creation: may be read without a lock at any time
// const after initialization: may be read without a lock after initialization
//   (after vfs_get() returns)
// other: must not be accessed without lock held or via appropriate helper.
struct vnode {
  int num;            // const after creation
  vnode_type_t type;  // const after initialization
  vnode_state_t state;

  // Lock for just the state of the vnode.  Will not be held across blocking
  // operations unless the vnode is being initialized or flushed/put (in which
  // case no other thread can be holding this mutex and attempting to take
  // another, unless there's a dependency cycle between filesystems).
  kmutex_t state_mu;

  // The length is cached here.  It will not be updated by the VFS code.
  int len;

  // Frequently-used metadata is cached here.  The VFS code may update these, in
  // which case the concrete fs function must write them back to the underlying
  // filesystem in put_vnone().
  // TODO(aoates): add an explicit (optional?) put_metadata() function that will
  // let the concrete fs proactively writeback metadata changes while the vnode
  // is still open.
  kuid_t uid;
  kgid_t gid;
  kmode_t mode;  // Doesn't include type bits (just permissions + sticky)

  // If this vnode is a mount point, the fsid_t of the mounted filesystem.
  fsid_t mounted_fs;

  // If this vnode is the root of a mounted fs (that's not the root fs), the
  // mount point on the parent fs.
  struct vnode* parent_mount_point;

  // TODO(aoates): consider replacing this with a refcount_t (which would
  // require reworking the inner VFS logic).
  atomic32_t refcount;

  char fstype[10];
  fs_t* fs;  // const after creation
  list_link_t fs_link;

  // If type == VNODE_BLOCKDEV || type == VNODE_CHARDEV, the underlying device.
  // TODO(aoates): put this and fifo in a union (and update usage sites to only
  // read one).
  apos_dev_t dev;

  // If type == VNODE_FIFO, the underlying FIFO.
  apos_fifo_t* fifo;

  // If type == VNODE_SOCKET, the underlying socket.  This will only be set for
  // actual sockets (sockets in the anonymous socket FS), not socket files on
  // real filesystems.
  socket_t* socket;

  // If type == VNODE_SOCKET and this is an actual socket file bound to a real
  // socket, then the bound socket.  Mutually exclusive with |socket| (above).
  socket_t* bound_socket;

  // The memobj_t corresponding to this vnode.
  memobj_t memobj;

  // Protects the vnode across blocking IO calls.
  kmutex_t mutex;
};
typedef struct vnode vnode_t;

// Initialize (and zero-out) a vnode_t.
void vfs_vnode_init(vnode_t* n, fs_t* fs, int num);

// Given a filesystem and a vnode number, return the corresponding vnode_t.
// This increments the vnode's refcount, which must be decremented later vith
// vfs_put.
//
// May block if the vnode is uninitialized or being initialized.  Safe to call
// with other vnodes locked.
//
// The caller must ensure the filesystem remains live through the call.  There
// are three normal ways to do this:
//  1) (most common) call it on another node's filesystem (e.g. a parent node).
//     Having a ref on the parent node ensures the filesystem stays alive.
//  2) With the filesystem's mount point node locked.
//  3) on a static filesystem (the root FS, a static anonfs, etc).
vnode_t* vfs_get(fs_t* fs, int vnode);

// Increment the given node's refcount.
void vfs_ref(vnode_t* n);

// Decrement the refcount of the given vnode, potentially releasing it's
// resources.  You must not access the vnode after calling this, unless you have
// another outstanding reference.
void vfs_put(vnode_t* n);

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

// Return the full pathname of the given vnode, which *must* be a directory, in
// the given buffer.  Returns the length of the string on success, or -error on
// error.
int vfs_get_vnode_dir_path(vnode_t* vnode, char* path_out, int size);

#endif
