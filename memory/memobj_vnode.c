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

#include "common/kassert.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kstring.h"
#include "memory/memobj_vnode.h"
#include "memory/memobj.h"
#include "memory/memory.h"
#include "proc/kthread.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"

static void vnode_ref(memobj_t* obj);
static void vnode_unref(memobj_t* obj);
static int vnode_get_page(memobj_t* obj, int page_offset, int writable,
                          bc_entry_t** entry_out);
static int vnode_put_page(memobj_t* obj, bc_entry_t* entry_out,
                          block_cache_flush_t flush_mode);
static int vnode_read_page(memobj_t* obj, int offset, void* buffer);
static int vnode_write_page(memobj_t* obj, int offset, const void* buffer);

static memobj_ops_t g_vnode_ops = {
  &vnode_ref,
  &vnode_unref,
  &vnode_get_page,
  &vnode_put_page,
  &vnode_read_page,
  &vnode_write_page,
};

static void vnode_ref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  kspin_lock(&obj->lock);
  KASSERT(obj->refcount > 0);
  obj->refcount++;
  kspin_unlock(&obj->lock);

  vnode_t* vnode = (vnode_t*)obj->data;
  vfs_ref(vnode);
}

static void vnode_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  kspin_lock(&obj->lock);
  KASSERT(obj->refcount > 0);
  obj->refcount--;
  kspin_unlock(&obj->lock);

  vnode_t* vnode = (vnode_t*)obj->data;
  vfs_put(vnode);
  // obj may now be invalid!
}

static int vnode_get_page(memobj_t* obj, int page_offset, int writable,
                          bc_entry_t** entry_out) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  return block_cache_get(obj, page_offset, entry_out);
}

static int vnode_put_page(memobj_t* obj, bc_entry_t* entry,
                          block_cache_flush_t flush_mode) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj == entry->obj);
  return block_cache_put(entry, flush_mode);
}

static int vnode_read_page(memobj_t* obj, int offset, void* buffer) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj->data != 0x0);

  vnode_t* vnode = (vnode_t*)obj->data;
  kmutex_lock(&vnode->mutex);
  int result = vnode->fs->read_page(vnode, offset, buffer);
  kmutex_unlock(&vnode->mutex);
  return result;
}

static int vnode_write_page(memobj_t* obj, int offset, const void* buffer) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj->data != 0x0);

  vnode_t* vnode = (vnode_t*)obj->data;
  kmutex_lock(&vnode->mutex);
  int result = vnode->fs->write_page(vnode, offset, buffer);
  kmutex_unlock(&vnode->mutex);
  return result;
}

void memobj_init_vnode(vnode_t* vnode) {
  memobj_t* obj = &vnode->memobj;
  memobj_base_init(obj);

  obj->type = MEMOBJ_VNODE;
  uint8_t id_array[sizeof(vnode->num) + sizeof(vnode->fs->id)];
  kmemcpy(id_array, &vnode->num, sizeof(vnode->num));
  kmemcpy(&id_array[sizeof(vnode->num)], &vnode->fs->id, sizeof(vnode->fs->id));
  obj->id =
      fnv_hash_array(id_array, sizeof(vnode->num) + sizeof(vnode->fs->id));
  obj->data = vnode;

  obj->ops = &g_vnode_ops;
}
