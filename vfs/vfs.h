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

#include <stdarg.h>
#include <stdint.h>

#include "common/posix_types.h"
#include "dev/dev.h"
#include "memory/memobj.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "vfs/dirent.h"
#include "vfs/fs.h"
#include "vfs/stat.h"
#include "vfs/vnode.h"

#define VFS_MAX_FILENAME_LENGTH 256
#define VFS_MAX_PATH_LENGTH 1024

// How many files can be open, globally, at once.
#define VFS_MAX_FILES 128

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

// Used internally (i.e. not exposed to userspace) to indicate a file that will
// be executed.  If set, vfs_open will check that the file is executable.
#define VFS_O_INTERNAL_EXEC 0x20

#define VFS_SEEK_SET 1
#define VFS_SEEK_CUR 2
#define VFS_SEEK_END 3

// Initialize the VFS.
void vfs_init(void);

// TODO(aoates): make a vfs-internal.h file with the internal-only functions in
// it.
// Log the current vnode cache.
void vfs_log_cache(void);

// Return how many vnodes are currently in the cache.
int vfs_cache_size(void);

// Looks up the given path and returns the refcount of the corresponding vnode,
// 0 if there is no matching vnode in the cache, or -errno if the path can't be
// found.
//
// Should only be used in tests.
int vfs_get_vnode_refcount_for_path(const char* path);

// Returns the vnode number at the given path, or -errno if the path can't be
// found.
//
// Should only be used in tests.
int vfs_get_vnode_for_path(const char* path);

// Open the given file in the current process, returning the file descriptor
// opened or -error on failure.
//
// If VFS_O_CREAT is given, the file will be created (if it doesn't already
// exist).
//
// If VFS_O_CREAT is given in |flags|, an additional argument (of type mode_t)
// is taken to be the mode of the file to be created (if necessary).
int vfs_open(const char* path, uint32_t flags, ...);

// Close the given file descriptor.  Returns 0 on success, or -error.
int vfs_close(int fd);

// Make a directory at the given path.  Returns 0 on success, or -error.
int vfs_mkdir(const char* path, mode_t mode);

// Create a file system node (regular file or special file).  mode must be one
// of the supported file types, bitwise OR'd with the mode of the file.
int vfs_mknod(const char* path, mode_t mode, apos_dev_t dev);

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

// Get the memobj_t associated with the given fd.  It will remain valid as long
// as the fd is open, unless the caller ref()s it.  The given mode must be
// compatible with the file's mode.  Returns 0 on success, or -error.
// TODO(aoates): how do we handle executable?
int vfs_get_memobj(int fd, uint32_t mode, memobj_t** memobj_out);

// Duplicate (as for fork()) procA's fds into procB.
void vfs_fork_fds(process_t* procA, process_t* procB);

// Returns 1 if the given fd refers to a TTY device, 0 otherwise.
int vfs_isatty(int fd);

// Stats the given path.  Returns 0 on success, or -error.
int vfs_lstat(const char* path, apos_stat_t* stat);

// Stats the given fd.  Returns 0 on success, or -error.
int vfs_fstat(int fd, apos_stat_t* stat);

// Changes the owner and/or group of the given path.  Returns 0 on success, or
// -error.
int vfs_lchown(const char* path, uid_t owner, gid_t group);

// Changes the owner and/or group of the given fd.  Returns 0 on success, or
// -error.
int vfs_fchown(int fd, uid_t owner, gid_t group);

// Changes the file mode of the given path.  Returns 0 on success, or -error.
int vfs_lchmod(const char* path, mode_t mode);

// Changes the file mode of the given fd.  Returns 0 on success, or -error.
int vfs_fchmod(int fd, mode_t mode);

#endif
