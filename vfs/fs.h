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

// Interface for concrete filesystem implementations.
#ifndef APOO_VFS_FS_H
#define APOO_VFS_FS_H

#include "vfs/fsid.h"
#include "vfs/vnode.h"

// Concrete filesystem interface.  One of these is instantiated by the concrete
// filesystem when it is initialized.
//
// All fs functions return 0 on success, or -errno on failure.
// TODO(aoates): make that actually the case!
//
// TODO(aoates): pinning and unpinning inodes and freeing them as needed.
struct fs {
  char fstype[10];
  apos_dev_t dev;  // The underlying device.
  fsid_t id;
  int open_vnodes;  // The number of open vnodes.
  kmutex_t rename_lock;

  // TODO(aoates): how does allocating the root inode/vnode work?

  // Allocate a vnode_t, with enough extra space for whatever data the FS will
  // want to store there.  The FS doesn't have to initialize any fields.
  vnode_t* (*alloc_vnode)(struct fs* fs);

  // Return the inode number of the root of the FS.
  int (*get_root)(struct fs* fs);

  // Fill in the vnode_t with data from the filesystem.  The vnode_t will have
  // been allocated with alloc_vnode and had the following fields initalized:
  // num, refcount, fs, mutex.  The FS should initialize the remaining fields
  // (and any FS-specific fields), and return 0 on success, or -errno on
  // failure.
  int (*get_vnode)(vnode_t* n);

  // Put a vnode that VFS no longer needs.  Make sure any pending writes are
  // flushed, then collect any resources that can be collected (such as inodes
  // with linkcounts of 0).  Do not free the vnode_t.
  int (*put_vnode)(vnode_t* n);

  // Return the inode number of the inode with the given name in a directory, or
  // -error on failure.
  int (*lookup)(vnode_t* parent, const char* name);

  // Create a regular file, block device, or character device in the given
  // directory.  type must be one of VNODE_{REGULAR,BLOCKDEV,CHARDEV}.  If
  // creating a block or character device, dev is the corresponding device to
  // bind it to.  Otherwise, it is ignored.
  //
  // Returns the inode number of the new file, or -error on failure.
  int (*mknod)(vnode_t* parent, const char* name, vnode_type_t type,
               apos_dev_t dev);

  // Create a directory in the given directory.  Returns the inode number of the
  // new directory, or -error on failure.
  //
  // Note: it must create the '.' and '..' entries in the directory as well.
  int (*mkdir)(vnode_t* parent, const char* name);

  // Remove an empty directory from the parent. Returns 0 on success, or -error.
  //
  // The filesystem must remove the '.' and '..' entries from the child before
  // rmdir() returns, but must not free the underlying inode.
  int (*rmdir)(vnode_t* parent, const char* name);

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
  // given name.  The underlying inode must not be destroyed if it's link count
  // is 0, since there may be outstanding VFS references.
  int (*unlink)(vnode_t* parent, const char* name);

  // Read several dirent_ts from the given (directory) vnode and fill the given
  // buffer.  Returns the number of bytes read into the buffer.  For subsequent
  // calls, the offset in the last dirent_t read should be passed in the offset
  // parameter, NOT the amount returned from the function.
  //
  // That is, offset is in concrete filesystem bytes, while the returned value
  // (and bufsize) are in buffer-size bytes.
  int (*getdents)(vnode_t* node, int offset, void* buf, int bufsize);

  // Stat the given vnode.   The VFS system will pre-populate the fields that
  // can be determined by examining the vnode only.  The concrete filesystem
  // must only fill in fields that only it can determine.
  int (*stat)(vnode_t* node, apos_stat_t* stat_out);

  // Create a symlink under the given parent, with the given contents.
  int (*symlink)(vnode_t* parent, const char* name, const char* path);

  // Read the contents of the given node, which must be a symbolic link, into
  // the given buffer.
  int (*readlink)(vnode_t* node, char* buf, int bufsize);

  // Truncate or extend the given node, as per ftruncate().
  int (*truncate)(vnode_t* node, off_t length);

  // Read and write a single page to/from the file.  This is use by the VM
  // subsystem when mmap'ing files.  The FS should read/write a page of data at
  // the given page_offset (which is in pages, not bytes) into/from the given
  // buffer, which will be page-aligned and sized.
  //
  // If there are fewer than a page of bytes in the file at the offset, the FS
  // must only read/write the data up to the length of the file.
  //
  // Note: the FS SHOULD NOT use the block cache to read from an underlying
  // device, since that data will simply be reinserted into the block cache
  // again.  If possible, the FS should read/write directly from the underlying
  // device into the buffer.
  //
  // Return 0 on success, or -errno on error.
  int (*read_page)(vnode_t* node, int page_offset, void* buf);
  int (*write_page)(vnode_t* node, int page_offset, const void* buf);

  // TODO(aoates): functions to add:
  //  * mknod
  //  * anything to do with attributes
  //  * freeing vnodes
};

// Initialize an fs_t with sane defaults.
void vfs_fs_init(fs_t* fs);

// Return the root FS.
fs_t* vfs_get_root_fs(void);

// Return the root vnode, with a reference on it.
vnode_t* vfs_get_root_vnode(void);

#endif
