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
#define VNODE_INVALID 0
#define VNODE_REGULAR   1
#define VNODE_DIRECTORY 2
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
//
// All fs functions return 0 on success, or -errno on failure.
// TODO(aoates): make that actually the case!
//
// TODO(aoates): pinning and unpinning inodes and freeing them as needed.
struct fs {
  // The root vnode.
  vnode_t* root;

  // Given an inode number, find the inode, and create and return the
  // corresponding vnode_t.  The returned vnode_t should have a refcount of 1.
  // Return 0 if the inode couldn't be found.
  vnode_t* (*get_vnode)(struct fs* fs, int);

  // Put a vnode that VFS no longer needs.  Make sure any pending writes are
  // flushed, then collect any resources that can be collected, and free the
  // vnode_t.
  void (*put_vnode)(vnode_t* n);

  // Create a regular file in the given directory.  Returns the inode number of
  // the new file, or -error on failure.
  int (*create)(vnode_t* parent, const char* name /*, mode? */);

  // Create a directory in the given directory.  Returns the inode number of
  // the new directory, or -error on failure.
  int (*mkdir)(vnode_t* parent, const char* name /*, mode? */);

  // Read up to bufsize bytes from the given vnode at the given offset.  Returns
  // the number of bytes read.
  int (*read)(vnode_t* vnode, int offset, void* buf, int bufsize);

  // Write up to bufsize bytes to the given vnode at the given offset.  Returns
  // the number of bytes written.
  int (*write)(vnode_t* vnode, int offset, const void* buf, int bufsize);

  // TODO(aoates): return error codes here instead of KASSERT()ing

  // Link the given vnode_t into the parent (which must be a directory) with the
  // given name.
  int (*link)(vnode_t* parent, vnode_t* vnode, const char* name);

  // Unlink the vnode in the parent (which must be a directory) that has the
  // given name.  If the underlying inode is not linked anywhere else, it can be
  // destroyed.
  int (*unlink)(vnode_t* parent, const char* name);

  // Read several dirent_ts from the given (directory) vnode and fill the given
  // buffer.  Returns the number of bytes read from the filesystem.
  int (*getdents)(vnode_t* node, int offset, void* buf, int bufsize);

  // TODO(aoates): functions to add:
  //  * mknod
  //  * anything to do with attributes
  //  * freeing vnodes
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
