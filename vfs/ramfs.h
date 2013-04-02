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

// Enable and disable artificial blocking for the ramfs.  If enabled, every call
// that's allowed to block will do so by calling scheduler_yield.  Useful for
// testing.
void ramfs_enable_blocking(fs_t* fs);
void ramfs_disable_blocking(fs_t* fs);

vnode_t* ramfs_alloc_vnode(struct fs* fs);
int ramfs_get_root(struct fs* fs);
int ramfs_get_vnode(vnode_t* vnode);
int ramfs_put_vnode(vnode_t* vnode);
int ramfs_lookup(vnode_t* parent, const char* name);
int ramfs_mknod(vnode_t* parent, const char* name,
                vnode_type_t type, dev_t dev);
int ramfs_mkdir(vnode_t* parent, const char* name);
int ramfs_rmdir(vnode_t* parent, const char* name);
int ramfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
int ramfs_write(vnode_t* vnode, int offset, const void* buf, int bufsize);
int ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
int ramfs_unlink(vnode_t* parent, const char* name);
int ramfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
int ramfs_read_page(vnode_t* vnode, int page_offset, void* buf);
int ramfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

#endif
