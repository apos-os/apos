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

#ifndef APOO_VFS_H
#define APOO_VFS_H

#include <stdint.h>

// vnode types.
#define VNODE_REGULAR   0
#define VNODE_DIRECTORY 1
// TODO(aoates): symlinks, special devices, etc.

struct fs;
typedef struct fs fs_t;

// A virtual node in the filesystem.  It is expected that concete filesystems
// will embed the vnode_t structure in their own, custom structure with
// additional metadata.
struct vnode {
  int num;
  int type;
  int len;

  int refcount;

  char fstype[10];
  fs_t* fs;
  // VFS impl pointer.
  //
  // TODO(aoates): mutex?
};
typedef struct vnode vnode_t;

// Concrete filesystem interface.  One of these is instantiated by the concrete
// filesystem when it is initialized.
// TODO(aoates): pinning and unpinning inodes and freeing them as needed.
struct fs {
  // The root vnode.
  vnode_t* root;

  // Allocate and initialize a new vnode for the FS.  Returns 0 if the FS is out
  // of free inodes.
  //
  // TODO(aoates): document what fields should be set and what shouldn't be set.
  //
  // Note: the returned vnode might end up being a regular file, or a directory,
  // or special file, etc.  Do we need additional hooks for initailizing those
  // types of files in an FS-specific way?
  vnode_t* (*alloc_vnode)(struct fs* fs);

  // Given a vnode number, find the vnode, and return the corresponding vnode_t
  // (allocating it if necessary).  Return 0 if the vnode couldn't be found.
  vnode_t* (*get_vnode)(struct fs* fs, int);

  // Read up to bufsize bytes from the given vnode at the given offset.  Returns
  // the number of bytes read.
  int (*read)(vnode_t* vnode, int offset, void* buf, int bufsize);

  // Write up to bufsize bytes to the given vnode at the given offset.  Returns
  // the number of bytes written.
  int (*write)(vnode_t* vnode, int offset, const void* buf, int bufsize);

  // TODO(aoates): return error codes here instead of KASSERT()ing

  // Link the given vnode_t into the parent (which must be a directory) with the
  // given name.
  void (*link)(vnode_t* parent, vnode_t* vnode, const char* name);

  // Unlink the vnode in the parent (which must be a directory) that has the
  // given name.  If the underlying inode is not linked anywhere else, it can be
  // destroyed.
  void (*unlink)(vnode_t* parent, const char* name);

  // Read several dirent_ts from the given (directory) vnode and fill the given
  // buffer.  Returns the number of bytes read from the filesystem.
  int (*getdents)(vnode_t* node, int offset, void* buf, int bufsize);
};
typedef struct fs fs_t;

// Syscall flags.
#define VFS_O_APPEND   0x01
#define VFS_O_CREAT    0x02
#define VFS_O_TRUNC    0x04
#define VFS_O_RDONLY   0x08
#define VFS_O_WRONLY   0x10
#define VFS_O_RDWR     0x20

// Initialize (and zero-out) a vnode_t.
void vfs_vnode_init(vnode_t* n);

#endif
