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

// A virtual filesystem where the contents of the files are determined by
// running callbacks in kernel mode.
#ifndef APOO_VFS_CBFS_H
#define APOO_VFS_CBFS_H

#include "common/list.h"
#include "common/kstring.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"

struct cbfs_inode;
typedef struct cbfs_inode cbfs_inode_t;

// A function that reads from a dynamic file in a cbfs.
typedef int (*cbfs_read_t)(fs_t* fs, void* arg, int vnode, int offset,
                           void* buf, int buflen);

// A function that looks up a dynamic vnode.
typedef int (*cbfs_lookup_t)(fs_t* fs, void* arg, int vnode,
                             cbfs_inode_t* inode_out);

// A function that lists entries in a dynamic directory in a cbfs.  It should
// create a list of cbfs_entry_ts, allocated from the given buffer, and pushed
// onto |list_out|.  It should return 0 on success.
typedef int (*cbfs_getdents_t)(fs_t* fs, int vnode_num, void* arg,
                               int offset, list_t* list_out, void* buf,
                               int buflen);

// A function that reads from a dynamic symlink in a cbfs.
typedef int (*cbfs_readlink_t)(fs_t* fs, void* arg, int vnode, void* buf,
                               int buflen);

typedef struct {
  int num;
  list_link_t link;
  char name[];
} cbfs_entry_t;

static inline size_t cbfs_entry_size(const char* name) {
  return sizeof(cbfs_entry_t) + kstrlen(name) + 1;
}

void cbfs_create_entry(cbfs_entry_t* entry, const char* name, int num);

// Create a cbfs_inode_t that represents a file.  Fills in the given
// cbfs_inode_t.
void cbfs_inode_create_file(cbfs_inode_t* inode, int num, cbfs_read_t read_cb,
                            void* read_arg, uid_t uid, gid_t gid, mode_t mode);

// Create a cbfs_inode_t that represents a directory.  Fills in the given
// cbfs_inode_t.
void cbfs_inode_create_directory(cbfs_inode_t* inode, int num, int parent_num,
                                 cbfs_getdents_t getdents_cb,
                                 void* getdents_arg, uid_t uid, gid_t gid,
                                 mode_t mode);

// Create a cbfs_inode_t that represents a dynamic symlink.  Fills in the given
// cbfs_inode_t.
void cbfs_inode_create_symlink(cbfs_inode_t* inode, int num,
                               cbfs_readlink_t readlink_cb, void* readlink_arg,
                               uid_t uid, gid_t gid);

// Create a cbfs.  The given callback, if non-NULL, will be run when looking up
// an unknown vnode.  It can be used to generate vnodes dynamically.
// max_static_vnode is the maximum inode/vnode number that the cbfs will
// allocate for static files and directories.  Use this to, e.g. set aside a
// range for dynamic use.
fs_t* cbfs_create(cbfs_lookup_t lookup_cb, void* lookup_arg,
                  int max_static_vnode);

// Free a created cbfs.
void cbfs_free(fs_t* fs);

// Create a file in the given cbfs.  When the file is read, the given callback
// will be run.
int cbfs_create_file(fs_t* fs, const char* name,
                     cbfs_read_t read_cb, void* arg, mode_t mode);

// Create a directory in the given cbfs.  If the getdents callback is non-NULL,
// it will be run when the directory is listed or a lookup is needed, and should
// return any dynamic directory entries in the directory (which shouldn't
// include '.' and '..').
int cbfs_create_directory(fs_t* fs, const char* path,
                          cbfs_getdents_t getdents_cb, void* arg, mode_t mode);

// Create a symlink in the given cbfs.  When the symlink is read, the given
// callback will be run.
int cbfs_create_symlink(fs_t* fs, const char* path, cbfs_readlink_t readlink_cb,
                        void* arg);

// Change the getdents callback of an existing directory.
int cbfs_directory_set_getdents(fs_t* fs, const char* path,
                                cbfs_getdents_t getdents_cb, void* arg);

#endif
