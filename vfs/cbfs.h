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

#include "vfs/fs.h"

struct cbfs_inode;
typedef struct cbfs_inode cbfs_inode_t;

typedef int (*cbfs_read_t)(fs_t* fs, void* arg, int offset,
                           void* buf, int buflen);

typedef int (*cbfs_lookup_t)(fs_t* fs, void* arg, int vnode,
                             cbfs_inode_t* inode_out);

// Create a cbfs_inode_t that represents a file.  Fills in the given
// cbfs_inode_t.
void cbfs_inode_create_file(cbfs_inode_t* inode, int num, cbfs_read_t read_cb,
                            void* read_arg, uid_t uid, gid_t gid, mode_t mode);

// Create a cbfs.  The given callback, if non-NULL, will be run when looking up
// an unknown vnode.  It can be used to generate vnodes dynamically.
fs_t* cbfs_create(cbfs_lookup_t lookup_cb, void* lookup_arg);

// Free a created cbfs.
void cbfs_free(fs_t* fs);

// Create a file in the given cbfs.  When the file is read, the given callback
// will be run.
int cbfs_create_file(fs_t* fs, const char* name,
                     cbfs_read_t read_cb, void* arg, mode_t mode);

#endif
