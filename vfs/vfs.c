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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/hashtable.h"
#include "kmalloc.h"
#include "proc/kthread.h"
#include "vfs/ramfs.h"
#include "vfs/vfs.h"

void vfs_vnode_init(vnode_t* n) {
  n->num = -1;
  n->type = -1;
  n->len = -1;
  n->refcount = 0;
  kmutex_init(&n->mutex);
}

#define VNODE_CACHE_SIZE 1000

static fs_t* g_root_fs = 0;
static htbl_t g_vnode_cache;

void vfs_init() {
  KASSERT(g_root_fs == 0);
  g_root_fs = ramfs_create_fs();
  htbl_init(&g_vnode_cache, VNODE_CACHE_SIZE);
}

vnode_t* vfs_get(int vnode_num) {
  vnode_t* vnode;
  int error = htbl_get(&g_vnode_cache, (uint32_t)vnode_num,
                             (void**)(&vnode));
  if (!error) {
    KASSERT(vnode->num == vnode_num);
    KASSERT(vnode->type != VNODE_INVALID);

    // Increment the refcount, then lock the mutex.  This ensures that the node
    // is initialized (since the thread creating it locks the mutex *before*
    // putting it in the table, and doesn't unlock it until it's initialized).
    vnode->refcount++;
    kmutex_lock(&vnode->mutex);
    kmutex_unlock(&vnode->mutex);
    return vnode;
  } else {
    // We need to create the vnode and backfill it from disk.
    vnode = g_root_fs->alloc_vnode(g_root_fs);
    vnode->num = vnode_num;
    vnode->type = VNODE_INVALID;
    vnode->len = -1;
    vnode->refcount = 1;
    vnode->fs = g_root_fs;
    kmutex_lock(&vnode->mutex);

    // This call could block, at which point other threads attempting to access
    // this node will block until we release the mutex.
    error = g_root_fs->get_vnode(vnode);
    if (error) {
      klogf("warning: error when getting inode %d: %s\n",
            vnode_num, errorname(-error));
      kfree(vnode);
      return 0x0;
    }

    kmutex_unlock(&vnode->mutex);
    return vnode;
  }
}

void vfs_put(vnode_t* vnode) {
  KASSERT(vnode->type != VNODE_INVALID);  // We must be fully initialized.
  vnode->refcount--;

  if (vnode->refcount == 0) {
    KASSERT(0 == htbl_remove(&g_vnode_cache, (uint32_t)vnode->num));
    // TODO(aoates): is this lock/unlock really neccessary?
    kmutex_lock(&vnode->mutex);
    vnode->fs->put_vnode(vnode);
    kmutex_unlock(&vnode->mutex);
    vnode->type = VNODE_INVALID;
    kfree(vnode);
  }
}
