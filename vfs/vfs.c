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
#include "common/kstring.h"
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

// Given a path /path/to/file, return the vnode_t* for the parent (/path/to),
// and the inode number of the child (file), or -1 if it doesn't exist.  If the
// path is the root path, parent_out and inode_out will both point at the root
// vnode.
//
// Returns 0 on success, or -error on failure.  Note that a missing directory on
// the path will result in a -ENOENT, while a missing final child will be a
// success.
//
// Returns *parent_out with a refcount.
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
static int lookup_path(const char* path, vnode_t** parent_out, int* inode_out) {
  int root_vnode = g_root_fs->get_root(g_root_fs);
  vnode_t* n = vfs_get(root_vnode);
  KASSERT(n);
  // Skip leading '/'.
  while (*path && *path == '/') path++;

  if (!*path) {
    // The path was the root node.
    *parent_out = n;
    *inode_out = root_vnode;
    return 0;
  }

  while(1) {
    KASSERT(*path);
    const char* name_end = kstrchrnul(path, '/');
    if (name_end - path >= MAX_FILENAME_LENGTH) {
      return -ENAMETOOLONG;
    }

    // TODO(aoates): get rid of this copy.
    char name[MAX_FILENAME_LENGTH];
    kstrncpy(name, path, name_end - path);
    name[name_end - path] = '\0';

    kmutex_lock(&n->mutex);
    int child_inode = n->fs->lookup(n, name);
    kmutex_unlock(&n->mutex);

    // Check for errors.
    if (child_inode < 0 && child_inode != -ENOENT) {
      vfs_put(n);
      return child_inode;
    }

    // Advance past any trailing slashes.
    while (*name_end && *name_end == '/') name_end++;

    // Check if we're done.
    if (!*name_end) {
      *parent_out = n;
      if (child_inode == -ENOENT) {
        *inode_out = -1;
      } else {
        *inode_out = child_inode;
      }
      return 0;
    }

    // Otherwise, lookup the child and keep going.
    vfs_put(n);
    n = vfs_get(child_inode);
    path = name_end;
  }
}

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
