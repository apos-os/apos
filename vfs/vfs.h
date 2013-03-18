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

#include "memory/memobj.h"
#include "proc/kthread.h"
#include "vfs/dirent.h"

#define VFS_MAX_FILENAME_LENGTH 256
#define VFS_MAX_PATH_LENGTH 1024

// How many files can be open, globally, at once.
#define VFS_MAX_FILES 128

// vnode types.  Keep these synchcronized with VNODE_TYPE_NAME in vfs.c.
#define VNODE_UNINITIALIZED 0
#define VNODE_INVALID 1
#define VNODE_REGULAR   2
#define VNODE_DIRECTORY 3
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

  // The memobj_t corresponding to this vnode.
  memobj_t memobj;

  // Protects the vnode across blocking IO calls.
  kmutex_t mutex;
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
  char fstype[10];
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

  // Create a regular file in the given directory.  Returns the inode number of
  // the new file, or -error on failure.
  int (*create)(vnode_t* parent, const char* name /*, mode? */);

  // Create a directory in the given directory.  Returns the inode number of the
  // new directory, or -error on failure.
  //
  // Note: it must create the '.' and '..' entries in the directory as well.
  int (*mkdir)(vnode_t* parent, const char* name /*, mode? */);

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

// Syscall flags.
// TODO(aoates): once we have userland, these should be the same constants as
// are used there.
#define VFS_MODE_MASK  0x03
#define VFS_O_RDONLY   0x00
#define VFS_O_WRONLY   0x01
#define VFS_O_RDWR     0x02

#define VFS_O_APPEND   0x04
#define VFS_O_CREAT    0x08
#define VFS_O_TRUNC    0x10  // TODO(aoates)

#define VFS_SEEK_SET 1
#define VFS_SEEK_CUR 2
#define VFS_SEEK_END 3

// Initialize the VFS.
void vfs_init();

// Return the root FS.
fs_t* vfs_get_root_fs();

// Return the root vnode, with a reference on it.
vnode_t* vfs_get_root_vnode();

// Initialize (and zero-out) a vnode_t.
void vfs_vnode_init(vnode_t* n);

// Given a filesystem and a vnode number, return the corresponding vnode_t.
// This increments the vnode's refcount, which must be decremented later vith
// vfs_put.
vnode_t* vfs_get(fs_t* fs, int vnode);

// TODO(aoates): make a vfs-internal.h file with the internal-only functions in
// it.
// Log the current vnode cache.
void vfs_log_cache();

// Return how many vnodes are currently in the cache.
int vfs_cache_size();

// Looks up the given path and returns the refcount of the corresponding vnode,
// 0 if there is no matching vnode in the cache, or -errno if the path can't be
// found.
int vfs_get_vnode_refcount_for_path(const char* path);

// Increment the given node's refcount.
void vfs_ref(vnode_t* n);

// Decrement the refcount of the given vnode, potentially releasing it's
// resources.  You must not access the vnode after calling this, unless you have
// another outstanding reference.
void vfs_put(vnode_t* n);

// Open the given file in the current process, returning the file descriptor
// opened or -error on failure.
//
// If VFS_O_CREAT is given, the file will be created (if it doesn't already
// exist).
//
// TODO(aoates): mode!
int vfs_open(const char* path, uint32_t flags);

// Close the given file descriptor.  Returns 0 on success, or -error.
int vfs_close(int fd);

// Make a directory at the given path.  Returns 0 on success, or -error.
// TODO(aoates): mode
int vfs_mkdir(const char* path);

// Remove an empty directory. Returns 0 on success, or -error.
int vfs_rmdir(const char* path);

// Unlink an entry from a directory.
int vfs_unlink(const char* path);

// Read up to count bytes from the given fd into buf, and advance the file
// position by that amount.  Returns the actual number of bytes read on success,
// or -error.
int vfs_read(int fd, void* buf, int count);

// Write up to count bytes from buf into the given fd, and advance the file
// position by that amount.  Returns the actual number of bytes written on
// success, or -error.
int vfs_write(int fd, const void* buf, int count);

// Seek the fd to the given offset, relative to whence.  Returns 0 on success,
// or -error.
int vfs_seek(int fd, int offset, int whence);

// Read several dirent_t structures from the file descriptor into the given
// buffer.  count is the size of the buffer in bytes.  Returns the number of
// bytes read on success, or -error.
int vfs_getdents(int fd, dirent_t* buf, int count);

// Return the full pathname of the current working directory in the given
// buffer.  Returns the length of the string on success, or -error on error.
int vfs_getcwd(char* path_out, int size);

// Change the current working directory.  Returns 0 on success, or -error.
int vfs_chdir(const char* path);

#endif
