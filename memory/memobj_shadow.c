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
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "memory/memobj_shadow.h"
#include "memory/memobj.h"
#include "memory/memory.h"

static void shadow_ref(memobj_t* obj);
static void shadow_unref(memobj_t* obj);
static int shadow_get_page(memobj_t* obj, int page_offset, int writable,
                           bc_entry_t** entry_out);
static int shadow_put_page(memobj_t* obj, bc_entry_t* entry_out,
                           block_cache_flush_t flush_mode);
static int shadow_read_page(memobj_t* obj, int offset, void* buffer);
static int shadow_write_page(memobj_t* obj, int offset, const void* buffer);

static memobj_ops_t g_shadow_ops = {
  &shadow_ref,
  &shadow_unref,
  &shadow_get_page,
  &shadow_put_page,
  &shadow_read_page,
  &shadow_write_page,
};

static void shadow_ref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  obj->refcount++;
}

static void shadow_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  KASSERT(obj->refcount > 0);
  obj->refcount--;
  // TODO(aoates): check if the only remaining refs are resident pages; if so,
  // flush and delete them, unref the underlying object, and delete this one.
  if (obj->refcount == 0) {
    memobj_t* subobj = (memobj_t*)obj->data;
    subobj->ops->unref(subobj);
    kfree(obj);
  }
}

static int shadow_get_page(memobj_t* obj, int page_offset, int writable,
                           bc_entry_t** entry_out) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  if (writable) {
    // Will either get an existing page, or copy a new page from the subobj (via
    // read_page) to write to.
    return block_cache_get(obj, page_offset, entry_out);
  } else {
    // First check if we have a copy of the page.
    const int result = block_cache_lookup(obj, page_offset, entry_out);
    if (result) return result;
    if (*entry_out != 0x0) return 0;

    // Didn't find it, get (a read-only copy of) it from the subobj.
    memobj_t* subobj = (memobj_t*)obj->data;
    return subobj->ops->get_page(subobj, page_offset, writable, entry_out);
  }
}

static int shadow_put_page(memobj_t* obj, bc_entry_t* entry,
                           block_cache_flush_t flush_mode) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Verify that the entry's object is in our shadow chain.
    memobj_t* verify_obj = obj;
    while (verify_obj->type == MEMOBJ_SHADOW && verify_obj != entry->obj) {
      verify_obj = (memobj_t*)verify_obj->data;
    }
    KASSERT(verify_obj == entry->obj);
  }
  return block_cache_put(entry, flush_mode);
}

static int shadow_read_page(memobj_t* obj, int offset, void* buffer) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  KASSERT(obj->data != 0x0);

  // Get a copy of the subobj's page and read into it.  We can't simply call
  // subobj->ops->read_page, because (for instance) if it were another shadow
  // object, we wouldn't get it's own copy of the page.
  memobj_t* subobj = (memobj_t*)obj->data;
  bc_entry_t* entry = 0x0;
  int result =
      subobj->ops->get_page(subobj, offset, 0 /* read-only */, &entry);
  if (result) return result;

  kmemcpy(buffer, entry->block, PAGE_SIZE);
  result = subobj->ops->put_page(subobj, entry, BC_FLUSH_NONE);
  return result;
}

static int shadow_write_page(memobj_t* obj, int offset, const void* buffer) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  KASSERT(obj->data != 0x0);

  // Do nothing --- shadow objects have no backing store.
  return 0;
}

memobj_t* memobj_create_shadow(memobj_t* subobj) {
  memobj_t* shadow_obj = (memobj_t*)kmalloc(sizeof(memobj_t));
  if (!shadow_obj) return 0x0;

  kmemset(shadow_obj, 0, sizeof(memobj_t));

  shadow_obj->type = MEMOBJ_SHADOW;
  shadow_obj->id = fnv_hash_array(&shadow_obj, sizeof(memobj_t*));
  shadow_obj->ops = &g_shadow_ops;
  shadow_obj->refcount = 0;
  shadow_obj->data = subobj;

  subobj->ops->ref(subobj);
  return shadow_obj;
}
