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

#ifndef APOO_VFS_VFS_MODE_H
#define APOO_VFS_VFS_MODE_H

#include "proc/process.h"
#include "vfs/vnode.h"

typedef enum {
  VFS_OP_READ = 1,
  VFS_OP_WRITE,
  VFS_OP_EXEC,
  VFS_OP_SEARCH,
} vfs_mode_op_t;

// Check whether the given operation in the given process can be done on the
// given vnode.  Returns 0 if the operation is allowed, or -error if not.
int vfs_check_mode(vfs_mode_op_t op, const process_t* proc,
                   const vnode_t* vnode);

// As above, but uses the ruid/rgid of the process instead of the euid.
int vfs_check_mode_rugid(vfs_mode_op_t op, const process_t* proc,
                         const vnode_t* vnode);

#endif
