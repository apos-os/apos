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

#include "vfs/vfs_test_util.h"

#include "common/kassert.h"
#include "vfs/vnode.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs.h"
#include "vfs/vnode_hash.h"

#define KLOG(...) klogfm(KL_VFS, __VA_ARGS__)

static bool g_force_no_files = false;

static void vfs_log_cache_iter(void* arg, uint32_t key, void* val) {
  vnode_t* vnode = (vnode_t*)val;
  KASSERT(key == vnode_hash_n(vnode));
  KLOG(INFO, "  %p { fs: %d inode: %d  type: %s  len: %d  refcount: %d }\n",
       vnode, vnode->fs->id, vnode->num, VNODE_TYPE_NAME[vnode->type],
       vnode->len, vnode->refcount);
}

void vfs_log_cache() {
  KLOG(INFO, "VFS vnode cache:\n");
  htbl_iterate(&g_vnode_cache, &vfs_log_cache_iter, 0x0);
}

static void vfs_cache_size_iter(void* arg, uint32_t key, void* val) {
  int* counter = (int*)arg;
  vnode_t* vnode = (vnode_t*)val;
  KASSERT(key == vnode_hash_n(vnode));
  (*counter)++;
}

int vfs_cache_size() {
  int size = 0;
  htbl_iterate(&g_vnode_cache, &vfs_cache_size_iter, &size);
  return size;
}

// TODO(aoates): can this be used as a helper for other functions as well?
static int vfs_get_vnode(const char* path, vnode_t** vnode_out) {
  vnode_t* root = get_root_for_path(path);
  vnode_t* parent = 0x0;
  char base_name[VFS_MAX_FILENAME_LENGTH];

  int error = lookup_path(root, path, lookup_opt(false),
                          &parent, 0x0, base_name);
  VFS_PUT_AND_CLEAR(root);
  if (error) {
    return error;
  }

  vnode_t* child = 0x0;
  if (base_name[0] == '\0') {
    child = VFS_MOVE_REF(parent);
  } else {
    // Lookup the child inode.
    error = lookup(&parent, base_name, &child);
    if (error < 0) {
      VFS_PUT_AND_CLEAR(parent);
      return error;
    }
    VFS_PUT_AND_CLEAR(parent);
  }
  *vnode_out = child;
  return 0;
}

int vfs_get_vnode_refcount_for_path(const char* path) {
  vnode_t* vnode = NULL;
  const int result = vfs_get_vnode(path, &vnode);
  if (result) return result;

  const int refcount = vnode->refcount - 1;
  VFS_PUT_AND_CLEAR(vnode);
  return refcount;
}

int vfs_get_vnode_for_path(const char* path) {
  vnode_t* vnode = NULL;
  const int result = vfs_get_vnode(path, &vnode);
  if (result) return result;

  const int num = vnode->num;
  VFS_PUT_AND_CLEAR(vnode);
  return num;
}

void vfs_set_force_no_files(bool f) {
  g_force_no_files = f;
}

bool vfs_get_force_no_files() {
  return g_force_no_files;
}

void vfs_make_nonblock(int fd) {
  file_t* file = 0x0;
  int result = lookup_fd(fd, &file);
  KASSERT(result == 0);
  KASSERT((file->flags & VFS_O_NONBLOCK) == 0);
  file->flags |= VFS_O_NONBLOCK;
}
