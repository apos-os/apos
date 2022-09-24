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

#include "arch/common/types.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "memory/memobj.h"
#include "memory/memobj_shadow.h"
#include "memory/memory.h"

typedef struct {
  memobj_t* subobj;
  // Lock for shadow-specific data.
  kmutex_t shadow_lock;
  // All extant block cache entries.  Map {offset -> bc_entry_t*}.  Each has an
  // additional pin on it to ensure it's kept resident even if not currently in
  // use by a process.
  htbl_t entries;
  // Set when we start clearing the entries table.
  bool cleaning_up;
} shadow_data_t;

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
  kspin_lock(&obj->lock);
  KASSERT(obj->refcount > 0);
  obj->refcount++;
  kspin_unlock(&obj->lock);
}

static void unpin_htbl_entry(void* arg, uint32_t key, void* val) {
  bc_entry_t* entry = (bc_entry_t*)val;
  KASSERT_DBG(key == entry->offset);
  block_cache_put(entry, BC_FLUSH_NONE);
}

static void shadow_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)obj->data;
  kspin_lock(&obj->lock);
  KASSERT(obj->refcount > 0);

  // Check if this is the last remaining refcount, other than our entries.
  if (!data->cleaning_up && obj->refcount == htbl_size(&data->entries) + 1) {
    // TODO(aoates): write a test that would detect not checking cleaning_up.
    // Set cleaning_up to ensure that only one thread gets to do this work, even
    // if we block in the htbl_clear() below and memory pressure triggers
    // putting one of our entries while we're in the middle of cleaning.
    data->cleaning_up = true;
    // The only remaining references are block cache entries; no one else can
    // reach the memobj and we can clean up.
    kspin_unlock(&obj->lock);
    // Unpin all entries and clear the table.  We do this before decrementing
    // the refcount to ensure the memobj is not freed (we still hold a
    // reference).
    htbl_clear(&data->entries, &unpin_htbl_entry, NULL);

    // Force the block cache to clear all our entries --- they should all be
    // unreferenced.  This prevents us from holding onto references to
    // underlying memobjs due to pages that will never be reused.
    // TODO(aoates): now that we force this at the end (rather than lazily
    // relying on cache pressure to clean up later), there might be a way to
    // rewrite all this logic to be more direct.
    int result = block_cache_free_all(obj);
    if (result) {
      // This shouldn't happen, but also no reason to die if it fails ---
      // nothing is left in a corrupt or incorrect state.
      klogfm(
          KL_GENERAL, ERROR,
          "unable to free all block cache entries for shadow object %p: %s\n",
          obj, errorname(-result));
    }

    kspin_lock(&obj->lock);
    // At this point we should still have at least one reference (this
    // thread's); if the above call failed, the BC entries may not have been
    // destroyed yet, in which case they will still hold references to this
    // memobj as well.
    KASSERT_DBG(obj->refcount >= 1);
  }
  int new_refcount = --obj->refcount;
  kspin_unlock(&obj->lock);

  // The block cache has finished with us, finish cleanup.
  if (new_refcount == 0) {
    data->subobj->ops->unref(data->subobj);
    htbl_cleanup(&data->entries);
    kfree(obj->data);
    kfree(obj);
  }
}

static int shadow_get_page(memobj_t* obj, int page_offset, int writable,
                           bc_entry_t** entry_out) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)obj->data;
  if (writable) {
    // Will either get an existing page, or copy a new page from the subobj (via
    // read_page) to write to.
    int result = block_cache_get(obj, page_offset, entry_out);
    if (result) return result;

    // If this is the first time we're seeing this entry, track it and add an
    // extra pin to ensure it's not deleted.
    // TODO(aoates): handle this differently when swap is added.
    kmutex_lock(&data->shadow_lock);
    void* tbl_val;
    bool needs_pin = false;
    if (htbl_get(&data->entries, page_offset, &tbl_val) != 0) {
      needs_pin = true;
      htbl_put(&data->entries, page_offset, *entry_out);
    } else {
      KASSERT_DBG(tbl_val == *entry_out);
    }
    kmutex_unlock(&data->shadow_lock);

    if (needs_pin) {
      // This can block, so must be called outside spinlock section.
      block_cache_add_pin(*entry_out);
    }
    return 0;
  } else {
    // First check if we have a copy of the page.
    const int result = block_cache_lookup(obj, page_offset, entry_out);
    if (result) return result;
    if (*entry_out != 0x0) return 0;

    // Didn't find it, get (a read-only copy of) it from the subobj.
    memobj_t* subobj = data->subobj;
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
      shadow_data_t* data = (shadow_data_t*)verify_obj->data;
      verify_obj = data->subobj;
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
  shadow_data_t* data = (shadow_data_t*)obj->data;
  memobj_t* subobj = data->subobj;
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

  memobj_base_init(shadow_obj);
  shadow_obj->type = MEMOBJ_SHADOW;
  shadow_obj->id = fnv_hash_array(&shadow_obj, sizeof(memobj_t*));
  shadow_obj->ops = &g_shadow_ops;
  shadow_data_t* data = (shadow_data_t*)kmalloc(sizeof(shadow_data_t));
  data->subobj = subobj;
  kmutex_init(&data->shadow_lock);
  htbl_init(&data->entries, 5);
  data->cleaning_up = false;
  shadow_obj->data = data;

  subobj->ops->ref(subobj);
  return shadow_obj;
}
