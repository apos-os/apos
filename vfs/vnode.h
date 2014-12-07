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

#include "memory/memobj.h"
#include "proc/kthread.h"
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
} vnode_type_t;

static const char* const VNODE_TYPE_NAME[] = {
  "UNINIT", "INV", "REG", "DIR", "BLK", "CHR", "FIFO",
};

// A virtual node in the filesystem.  It is expected that concete filesystems
// will embed the vnode_t structure in their own, custom structure with
// additional metadata.
struct vnode {
  int num;
  vnode_type_t type;

  // The length is cached here.  It will not be updated by the VFS code.
  int len;

  // Frequently-used metadata is cached here.  The VFS code may update these, in
  // which case the concrete fs function must write them back to the underlying
  // filesystem in put_vnone().
  // TODO(aoates): add an explicit (optional?) put_metadata() function that will
  // let the concrete fs proactively writeback metadata changes while the vnode
  // is still open.
  uid_t uid;
  gid_t gid;
  mode_t mode;  // Doesn't include type bits (just permissions + sticky)

  // If this vnode is a mount point, the fsid_t of the mounted filesystem.
  fsid_t mounted_fs;

  // If this vnode is the root of a mounted fs (that's not the root fs), the
  // mount point on the parent fs.
  struct vnode* parent_mount_point;

  int refcount;

  char fstype[10];
  fs_t* fs;

  union {
    // If type == VNODE_BLOCKDEV || type == VNODE_CHARDEV, the underlying device.
    apos_dev_t dev;

    // If type == VNODE_FIFO, the underlying FIFO.
    apos_fifo_t* fifo;
  };

  // The memobj_t corresponding to this vnode.
  memobj_t memobj;

  // Protects the vnode across blocking IO calls.
  kmutex_t mutex;
  // VFS impl pointer.
  //
  // TODO(aoates): mutex?
};
typedef struct vnode vnode_t;

// Initialize (and zero-out) a vnode_t.
void vfs_vnode_init(vnode_t* n, int num);

// Given a filesystem and a vnode number, return the corresponding vnode_t.
// This increments the vnode's refcount, which must be decremented later vith
// vfs_put.
vnode_t* vfs_get(fs_t* fs, int vnode);
//
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
