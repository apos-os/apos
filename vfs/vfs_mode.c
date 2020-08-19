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

#include "vfs/vfs_mode.h"

#include "common/errno.h"
#include "proc/user.h"

static int vfs_check_mode_internal(vfs_mode_op_t op,
                                   const vnode_t* vnode, bool is_superuser,
                                   kuid_t uid, kgid_t gid) {
  if (is_superuser) {
    if (op == VFS_OP_EXEC && !(vnode->mode & VFS_S_IXUSR) &&
        !(vnode->mode & VFS_S_IXGRP) && !(vnode->mode & VFS_S_IXOTH)) {
      return -EACCES;
    }
    return 0;
  }

  switch (op) {
    case VFS_OP_READ:
      if (vnode->uid == uid) {
        if (vnode->mode & VFS_S_IRUSR) return 0;
      } else if (vnode->gid == gid) {
        if (vnode->mode & VFS_S_IRGRP) return 0;
      } else if (vnode->mode & VFS_S_IROTH) {
        return 0;
      }
      break;

    case VFS_OP_WRITE:
      if (vnode->uid == uid) {
        if (vnode->mode & VFS_S_IWUSR) return 0;
      } else if (vnode->gid == gid) {
        if (vnode->mode & VFS_S_IWGRP) return 0;
      } else if (vnode->mode & VFS_S_IWOTH) {
        return 0;
      }
      break;

    case VFS_OP_EXEC:
    case VFS_OP_SEARCH:
      if (vnode->uid == uid) {
        if (vnode->mode & VFS_S_IXUSR) return 0;
      } else if (vnode->gid == gid) {
        if (vnode->mode & VFS_S_IXGRP) return 0;
      } else if (vnode->mode & VFS_S_IXOTH) {
        return 0;
      }
      break;
  }

  return -EACCES;
}

int vfs_check_mode(vfs_mode_op_t op, const process_t* proc,
                   const vnode_t* vnode) {
  return vfs_check_mode_internal(op, vnode, proc_is_superuser(proc),
                                 proc->euid, proc->egid);
}

int vfs_check_mode_rugid(vfs_mode_op_t op, const process_t* proc,
                         const vnode_t* vnode) {
  return vfs_check_mode_internal(op, vnode, proc_is_superuser(proc),
                                 proc->ruid, proc->rgid);
}
