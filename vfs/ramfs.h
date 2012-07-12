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

// Simple in-memory filesystem.
#ifndef APOO_RAMFS_H
#define APOO_RAMFS_H

#include <stdint.h>

#include "vfs/vfs.h"

// Initialize a new ramfs and return it.
fs_t* ramfs_create_fs();

vnode_t* ramfs_get_vnode(fs_t* fs, int vnode);
void ramfs_put_vnode(vnode_t* vnode);
int ramfs_create(vnode_t* parent, const char* name);
int ramfs_mkdir(vnode_t* parent, const char* name);
int ramfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
int ramfs_write(vnode_t* vnode, int offset, const void* buf, int bufsize);
int ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
int ramfs_unlink(vnode_t* parent, const char* name);
int ramfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);

#endif
