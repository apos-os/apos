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
#include "vfs/vfs.h"

static void vnode_ref(memobj_t* obj);
static void vnode_unref(memobj_t* obj);
static int vnode_read_page(memobj_t* obj, int offset, void* buffer);
static int vnode_write_page(memobj_t* obj, int offset, const void* buffer);

static memobj_ops_t g_vnode_ops = {
  &vnode_ref,
  &vnode_unref,
  &vnode_read_page,
  &vnode_write_page,
};

static void vnode_ref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  obj->refcount++;
  vnode_t* vnode = (vnode_t*)obj->data;
  vfs_ref(vnode);
}

static void vnode_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj->refcount > 0);
  obj->refcount--;
  vnode_t* vnode = (vnode_t*)obj->data;
  vfs_put(vnode);
  // obj may now be invalid!
}

static int vnode_read_page(memobj_t* obj, int offset, void* buffer) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj->data != 0x0);

  vnode_t* vnode = (vnode_t*)obj->data;
  return vnode->fs->read_page(vnode, offset, buffer);
}

static int vnode_write_page(memobj_t* obj, int offset, const void* buffer) {
  KASSERT(obj->type == MEMOBJ_VNODE);
  KASSERT(obj->data != 0x0);

  vnode_t* vnode = (vnode_t*)obj->data;
  return vnode->fs->write_page(vnode, offset, buffer);
}

void memobj_init_vnode(vnode_t* vnode) {
  memobj_t* obj = &vnode->memobj;
  kmemset(obj, 0, sizeof(memobj_t));

  obj->type = MEMOBJ_VNODE;
  // TODO(aoates): include filesystem number when mounting is supported.
  obj->id = fnv_hash(vnode->num);
  obj->refcount = 0;
  obj->data = vnode;

  obj->ops = &g_vnode_ops;
}
