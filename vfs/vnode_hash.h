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

#ifndef APOO_VFS_VNODE_HASH_H
#define APOO_VFS_VNODE_HASH_H

#include "common/hash.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"


static uint32_t vnode_hash(const fs_t* fs, int vnode_num) {
  return fnv_hash_concat(fs->id, (uint32_t)vnode_num);
}

static uint32_t vnode_hash_n(const vnode_t* vnode) {
  return vnode_hash(vnode->fs, vnode->num);
}

#endif
