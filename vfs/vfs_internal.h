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
} mounted_fs_t;

extern mounted_fs_t g_fs_table[VFS_MAX_FILESYSTEMS];
extern htbl_t g_vnode_cache;
extern file_t* g_file_table[VFS_MAX_FILES];

// Given a pointer to a vnode, if it is a mount point, replace it with the
// mounted filesystem's root directory, continuing until the mounts are fully
// resolved.  If there is an error, returns -error.
int resolve_mounts(vnode_t** vnode);

// Given a vnode and child name, lookup the vnode of the child.  Returns 0 on
// success (and refcounts the child).
//
// Requires a lock on the parent to ensure that the child isn't removed between
// the call to parent->lookup() and vfs_get(child).
int lookup_locked(vnode_t* parent, const char* name, vnode_t** child_out);

// Convenience wrapper that locks the parent around a call to lookup_locked().
int lookup(vnode_t* parent, const char* name, vnode_t** child_out);

// Similar to lookup(), but does the reverse: given a directory and an inode
// number, return the corresponding name, if the directory has an entry for
// that inode number.
//
// Returns the length of the name on success, or -error.
int lookup_by_inode(vnode_t* parent, int inode, char* name_out, int len);

// Given a vnode and a path path/to/myfile relative to that vnode, return the
// vnode_t of the directory part of the path, and copy the base name of the path
// (without any trailing slashes) into base_name_out.
//
// base_nome_out must be AT LEAST VFS_MAX_FILENAME_LENGTH long.
//
// Returns 0 on success, or -error on failure (in which case the contents of
// parent_out and base_name_out are undefined).
//
// Returns *parent_out with a refcount unless there was an error.
// TODO(aoates): this needs to handle symlinks!
// TODO(aoates): things to test:
//  * regular path
//  * root directory
//  * path ending in file
//  * path ending in directory
//  * trailing slashes
//  * no leading slash (?)
//  * non-directory in middle of path (ENOTDIR)
//  * non-existing in middle of path (ENOENT)
int lookup_path(vnode_t* root, const char* path,
                vnode_t** parent_out, char* base_name_out);

// Similar to lookup_path(), but does a full lookup of an existing file.  Used
// for operations that simply work on an existing file, and don't need to worry
// about the path root, basename, parent directory, etc.
//
// If |resolve_mount| is non-zero, the final child will be resolved if it is a
// mount point (you probably want this).
//
// Returns the child WITH A REFERENCE in |child_out| if it exists, or -error
// otherwise.
int lookup_existing_path(const char* path, vnode_t** child_out,
                         int resolve_mount);

// Lookup a file_t from an open fd.  Returns the corresponding file_t* in
// |file_out| WITHOUT A REFERENCE, or -error otherwise.
int lookup_fd(int fd, file_t** file_out);

// Returns the appropriate root node for the given path, either the fs root or
// the process's cwd.
vnode_t* get_root_for_path(const char* path);

#endif
