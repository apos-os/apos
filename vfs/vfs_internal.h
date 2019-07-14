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

// Internal definitions and utilies to be used within the VFS module.
#ifndef APOO_VFS_VFS_INTERNAL_H
#define APOO_VFS_VFS_INTERNAL_H

#include "common/hashtable.h"
#include "proc/process.h"
#include "vfs/file.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"

// How many files can be open, globally, at once.
#define VFS_MAX_FILES 128

// How many filesystems can be mounted, globally, at once.
#define VFS_MAX_FILESYSTEMS 10

// A mounted filesystem.
typedef struct {
  vnode_t* mount_point;
  fs_t* fs;
  vnode_t* mounted_root;
} mounted_fs_t;

extern mounted_fs_t g_fs_table[VFS_MAX_FILESYSTEMS];
extern htbl_t g_vnode_cache;
extern file_t* g_file_table[VFS_MAX_FILES];

// Given a pointer to a vnode, if it is a mount point, replace it with the
// mounted filesystem's root directory, continuing until the mounts are fully
// resolved.  If there is an error, returns -error.
int resolve_mounts(vnode_t** vnode);

// The opposite of the above.  Given a pointer to a vnode, *and a child name*,
// if the child name is '..' and the vnode is a mounted fs root, replace the
// vnode with the mount point.
void resolve_mounts_up(vnode_t** parent, const char* child_name);

// Options that determine how we do path lookups.
typedef struct lookup_options {
  bool resolve_final_symlink;
  // If true, the ruid/rgid will be checked for access permissions instead of
  // the euid/egid.  Most syscalls don't want this.  It defaults to false.
  bool check_real_ugid;
  bool resolve_final_mount;
} lookup_options_t;

static inline lookup_options_t lookup_opt(bool resolve_final_symlink) {
  lookup_options_t opt;
  opt.resolve_final_symlink = resolve_final_symlink;
  opt.check_real_ugid = false;
  opt.resolve_final_mount = true;
  return opt;
}

// Resolve the given vnode if it is a symlink, replacing it with the final
// target.  Resolves the symlink path relative to the parent.  Also replaces the
// parent pointer with the parent of the symlink target.  On error, the child
// pointer will point to *some* vnode, but not necessarily the original one, and
// must still be vfs_put().
//
// If the symlink is resolved, the new basename of the symlink is copied to
// |base_name_out|.  If the node isn't a symlink, |base_name_out| is left
// unchanged.
//
// If |allow_nonexistant_final| is non-zero, and the final element of the
// symlink doesn't exist, resolve_symlink() will return 0 instead of -ENOENT,
// but will set |*child_ptr| to 0x0.
int resolve_symlink(int allow_nonexistant_final, lookup_options_t opt,
                    vnode_t** parent_ptr, vnode_t** child_ptr,
                    char* base_name_out, int max_recursion);

// Given a vnode and child name, lookup the vnode of the child.  Returns 0 on
// success (and refcounts the child).
//
// Requires a lock on the parent to ensure that the child isn't removed between
// the call to parent->lookup() and vfs_get(child).
//
// NOTE: the caller MUST call resolve_mounts_up() before calling this (unlike
// with lookup()) for mount points to be handled correctly!
int lookup_locked(vnode_t* parent, const char* name, vnode_t** child_out);

// Convenience wrapper that calls resolve_mounts_up() and locks the parent
// around a call to lookup_locked().
//
// NOTE: |parent| may be modified by this call, if it traverses a mount point.
int lookup(vnode_t** parent, const char* name, vnode_t** child_out);

// Similar to lookup(), but does the reverse: given a directory and an inode
// number, return the corresponding name, if the directory has an entry for
// that inode number.
//
// Returns the length of the name on success, or -error.
int lookup_by_inode(vnode_t* parent, int inode, char* name_out, int len);

// Looks up a path relative to the root inode.  Looks up every element of the
// path, following symlinks, until the last element.  If resolve_final_symlink
// is set, and the last element is a symlink, it will be followed.  Otherwise,
// the symlink will be returned.
//
// If |parent_out| is non-null, it will be set to the parent of the final node.
// If |child_out| is non-null, and the final element exists, it will be set to
// the final element.  |base_name_out| (which must be at least
// VFS_MAX_FILENAME_LENGTH bytes long) will be set to the final element of the
// path, whether it exists or not.
//
// Returns |*parent_out| with a ref unless there was an error.  Returns
// |*child_out| with a ref unless there was an error or the last element doesn't
// exist.
//
// IMPORTANT: if the final element doesn't exist, the call succeeds (returns 0),
// but *child_out will be set to 0x0.
int lookup_path(vnode_t* root, const char* path, lookup_options_t options,
                vnode_t** parent_out, vnode_t** child_out, char* base_name_out);

// Similar to lookup_path(), but does a full lookup of an existing file.  Used
// for operations that simply work on an existing file, and don't need to worry
// about the path root, basename, parent directory, etc.
//
// Returns the child WITH A REFERENCE in |child_out| if it exists, or -error
// otherwise.  Returns the parent of the child, also with a reference in
// |parent_out|, unless |parent_out| is null.
int lookup_existing_path(const char* path, lookup_options_t options,
                         vnode_t** parent_out, vnode_t** child_out);

// Lookup a file_t from an open fd.  Returns the corresponding file_t* in
// |file_out| with a reference, or -error otherwise.
int lookup_fd(int fd, file_t** file_out);

// Reference and unreference a file.  You must use these rather than manipulate
// the refcount directly.
//
// If the file's refcount hits zero, the associated resources are closed and
// freed.
void file_ref(file_t* f);
void file_unref(file_t* f);

static inline int is_valid_fd(int fd) {
  return fd >= 0 && fd < PROC_MAX_FDS;
}

// Returns the appropriate root node for the given path, either the fs root or
// the process's cwd.
vnode_t* get_root_for_path(const char* path);

// As above, but returns the given parent (with an extra ref) if the path isn't
// absolute.
vnode_t* get_root_for_path_with_parent(const char* path,
                                       vnode_t* relative_root);

// Open the given vnode_t, allocating a file descriptor and file_t, etc.
// block is independent of (flags & VFS_O_NONBLOCK), since callers may want to
// create a non-blocking fd, but not block during opening (e.g. pipes).
int vfs_open_vnode(vnode_t* vnode, int flags, bool block);

// Creates a socket file or returns an error.  If successful, returns the open
// node with a reference in |vnode_out|.
int vfs_mksocket(const char* path, mode_t mode, vnode_t** vnode_out);

#endif
