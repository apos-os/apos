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
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "memory/memobj.h"
#include "memory/memobj_shadow.h"
#include "memory/memory.h"
#include "proc/kthread.h"

#define SHADOW_CHAIN_MAX 100

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

static void unpin_htbl_entry(void* arg, htbl_key_t key, void* val) {
  bc_entry_t* entry = (bc_entry_t*)val;
  KASSERT_DBG(key == entry->offset);
  block_cache_put(entry, BC_FLUSH_NONE);
}

// Add the given entry to the parent's object's table if it's not currently in
// there.  Returns true if added.
static void maybe_add_to_entry_table(bc_entry_t* entry) {
  shadow_data_t* data = (shadow_data_t*)entry->obj->data;
  kmutex_assert_is_held(&data->shadow_lock);
  void* tbl_val;
  // If this is the first time we're seeing this entry, track it and add an
  // extra pin to ensure it's not deleted.
  // TODO(aoates): handle this differently when swap is added.
  if (htbl_get(&data->entries, entry->offset, &tbl_val) != 0) {
    block_cache_add_pin(entry);
    htbl_put(&data->entries, entry->offset, entry);
  } else {
    KASSERT_DBG(tbl_val == entry);
  }
}

// Try to remove any entries that exist in the parent shadow object.
static bool shadow_maybe_migrate_entry(void* arg, htbl_key_t key, void* val) {
  bc_entry_t* entry = (bc_entry_t*)val;
  KASSERT_DBG(key == entry->offset);
  KASSERT_DBG(key <= UINT32_MAX);

  shadow_data_t* parent = (shadow_data_t*)arg;
  bc_entry_t* new_entry = NULL;
  int migrate_result = block_cache_migrate(entry, parent->me, &new_entry);
  if (migrate_result == 0) {
    entry = NULL;  // Possibly dead pointer, safety measure.
    klogfm(KL_MEMORY, DEBUG2,
           "Migrated shadow entry (parent: %p  offset: %u)\n", parent->me,
           (uint32_t)key);

    // Add the new entry to the parent's table if necessary.
    maybe_add_to_entry_table(new_entry);

    // TODO(aoates): consider moving things around so we don't add a pin then
    // immediately remove it.
    block_cache_put(new_entry, BC_FLUSH_NONE);
    // Entry was migrated or discarded.  Remove from our table.
    return false;
  }

  // Entry was unable to be migrated for some reason; retain it.
  return true;
}

static void shadow_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)obj->data;
  KASSERT_DBG(data->me == obj);

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
    // Safe to read subobj without big lock held; no one can reach us anymore.
    if (data->subobj) {
      data->subobj->ops->unref(data->subobj);
    }

    htbl_cleanup(&data->entries);
    kfree(obj->data);
    kfree(obj);
  }
}

static int shadow_get_page(memobj_t* obj, int page_offset, int writable,
                           bc_entry_t** entry_out) {
  KASSERT(obj->type == MEMOBJ_SHADOW);
  shadow_data_t* data = (shadow_data_t*)obj->data;
  kmutex_lock(&data->shadow_lock);
  int result = 0;
  if (writable) {
    // Will either get an existing page, or copy a new page from the subobj (via
    // read_page) to write to.
    result = block_cache_get(obj, page_offset, entry_out);
    if (result) goto done;

    // If this is the first time we're seeing this entry, track it and add an
    // extra pin to ensure it's not deleted.
    // TODO(aoates): handle this differently when swap is added.
    maybe_add_to_entry_table(*entry_out);
  } else {
    // First check if we have a copy of the page.
    result = block_cache_lookup(obj, page_offset, entry_out);
    if (result) goto done;
    if (*entry_out != 0x0) goto done;

    // Didn't find it, get (a read-only copy of) it from the subobj.
    memobj_t* subobj = data->subobj;
    result = subobj->ops->get_page(subobj, page_offset, writable, entry_out);
  }

done:
  kmutex_unlock(&data->shadow_lock);
  return result;
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
  // object, we wouldn't get its own copy of the page.
  shadow_data_t* data = (shadow_data_t*)obj->data;
  kmutex_assert_is_held(&data->shadow_lock);
  memobj_t* subobj = data->subobj;
  bc_entry_t* entry = 0x0;
  int result =
      subobj->ops->get_page(subobj, offset, 0 /* read-only */, &entry);
  if (result) {
    return result;
  }

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

// Collapses entries in the shadow chain below the given object, and returns the
// final length of that chain.
// TODO(aoates): look for a way to express this locking (partially or fully)
static int collapse_and_count(memobj_t* parent) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT_DBG(parent->type == MEMOBJ_SHADOW);
  shadow_data_t* parent_data = (shadow_data_t*)parent->data;
  kmutex_lock(&parent_data->shadow_lock);

  kspin_lock(&parent->lock);
  KASSERT(parent->refcount > 0);
  kspin_unlock(&parent->lock);

  memobj_t* obj = parent_data->subobj;
  int depth = 1;
  // Loop invariant:
  //  1) parent and parent_data point at a shadow object
  //  2) parent is locked
  //  3) obj points at the parent's subobj, which could be any kind.
  while (obj->type == MEMOBJ_SHADOW) {
    KASSERT_DBG(parent_data == parent->data);
    KASSERT_DBG(obj == parent_data->subobj);
    kmutex_assert_is_held(&parent_data->shadow_lock);

    shadow_data_t* data = obj->data;
    kmutex_lock(&data->shadow_lock);
    // Check if we have no refs besides our entries --- if so, eligable for
    // collapse.
    // TODO(aoates): this won't catch if we have pending 'dead' entries
    // consuming our refcount.  That can only happen now due to a previous
    // collapse; in the future could be triggered by swap as well.
    kspin_lock(&obj->lock);
    KASSERT_DBG(obj->refcount >= htbl_size(&data->entries) + 1);
    if (obj->refcount > htbl_size(&data->entries) + 1) {
      kspin_unlock(&obj->lock);
      goto skip_this_one;
    }

    // Sanity checks.
    KASSERT_DBG(obj->refcount == htbl_size(&data->entries) + 1);
    KASSERT(!data->cleaning_up);
    kspin_unlock(&obj->lock);

    // Migrate pages to parent.
    int removed =
        htbl_filter(&data->entries, &shadow_maybe_migrate_entry, parent_data);
    if (removed > 0) {
      klogfm(KL_MEMORY, DEBUG, "Migrated %d entries from shadow object %p\n",
             removed, obj);
    }
    if (htbl_size(&data->entries) > 0) {
      klogfm(KL_MEMORY, DEBUG, "Unable to migrate %d entries\n",
             htbl_size(&data->entries));
      // Continue collapsing down the shadow chain.
      goto skip_this_one;
    }

    // Final step --- splice it out of the shadow chain and unref.
    kmutex_unlock(&data->shadow_lock);
    KASSERT_DBG(parent_data->subobj == obj);
    parent_data->subobj = data->subobj;  // Transfer reference.
    data->subobj = NULL;
    shadow_unref(obj);

    // Keep parent the same, but try again with the new child --- like yanking
    // up an anchor chain link by link.  The depth doesn't increase.
    obj = parent_data->subobj;
    continue;

  skip_this_one:;
    shadow_data_t* old_parent_data = parent_data;  // For code clarity.
    parent = obj;
    parent_data = parent->data;
    obj = parent_data->subobj;
    kmutex_unlock(&old_parent_data->shadow_lock);
    depth++;
  }
  kmutex_unlock(&parent_data->shadow_lock);
  return depth;
}

memobj_t* memobj_create_shadow(memobj_t* subobj) {
  if (subobj->type == MEMOBJ_SHADOW) {
    // TODO(aoates): check for and handle too-deep chains.
    collapse_and_count(subobj);
  }

  memobj_t* shadow_obj = (memobj_t*)kmalloc(sizeof(memobj_t));
  if (!shadow_obj) return 0x0;

  memobj_base_init(shadow_obj);
  shadow_obj->type = MEMOBJ_SHADOW;
  shadow_obj->id = fnv_hash_array(&shadow_obj, sizeof(memobj_t*));
  shadow_obj->ops = &g_shadow_ops;
  shadow_data_t* data = (shadow_data_t*)kmalloc(sizeof(shadow_data_t));
  data->me = shadow_obj;
  data->subobj = subobj;
  kmutex_init(&data->shadow_lock);
  htbl_init(&data->entries, 5);
  data->cleaning_up = false;
  shadow_obj->data = data;

  subobj->ops->ref(subobj);
  return shadow_obj;
}
