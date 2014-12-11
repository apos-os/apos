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

#ifndef APOO_VFS_ANONFS_H
#define APOO_VFS_ANONFS_H

#include "vfs/vnode.h"

// A pseudo-filesystem for anonymous file-like objects (FIFOs, sockets, etc).
// Each filesytem has an associated vnode type, and it generates only vnodes of
// that type.
//
// All operations except alloc_vnode, get_vnode, and put_vnode are stubbed out
// (and should never be called in normal operation).

// Create a new anonfs that generates vnodes of the given type.
fs_t* anonfs_create(vnode_type_t type);

// Allocate and return an unused vnode on the given anonfs.  This doesn't do
// anything besides guarantee the returned vnode is unique; it will presumably
// be later passed to vfs_get()  to get a vnode.
ino_t anonfs_create_vnode(fs_t* fs);

#endif
