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
#include "memory/memobj_anon.h"
#include "memory/memobj.h"
#include "memory/memory.h"

static void anon_ref(memobj_t* obj);
static void anon_unref(memobj_t* obj);
static int anon_get_page(memobj_t* obj, int page_offset, int writable,
                       bc_entry_t** entry_out);
static int anon_put_page(memobj_t* obj, bc_entry_t* entry_out,
                       block_cache_flush_t flush_mode);
static int anon_read_page(memobj_t* obj, int page_offset, void* buffer);
static int anon_write_page(memobj_t* obj, int page_offset, const void* buffer);

static memobj_ops_t g_anon_ops = {
  &anon_ref,
  &anon_unref,
  &anon_get_page,
  &anon_put_page,
  &anon_read_page,
  &anon_write_page,
};

static void anon_ref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_ANON);
  obj->refcount++;
}

static void anon_unref(memobj_t* obj) {
  KASSERT(obj->type == MEMOBJ_ANON);
  KASSERT(obj->refcount > 0);
  obj->refcount--;
  if (obj->refcount == 0) {
    kfree(obj);
  }
}

static int anon_get_page(memobj_t* obj, int page_offset, int writable,
                       bc_entry_t** entry_out) {
  KASSERT(obj->type == MEMOBJ_ANON);
  return block_cache_get(obj, page_offset, entry_out);
}

static int anon_put_page(memobj_t* obj, bc_entry_t* entry,
                       block_cache_flush_t flush_mode) {
  KASSERT(obj->type == MEMOBJ_ANON);
  KASSERT(obj == entry->obj);
  return block_cache_put(entry, flush_mode);
}

static int anon_read_page(memobj_t* obj, int page_offset, void* buffer) {
  KASSERT(obj->type == MEMOBJ_ANON);
  kmemset(buffer, 0, PAGE_SIZE);
  return 0;
}

static int anon_write_page(memobj_t* obj, int page_offset, const void* buffer) {
  KASSERT(obj->type == MEMOBJ_ANON);
  // Nothing to do.
  return 0;
}

memobj_t* memobj_create_anon() {
  memobj_t* anon_obj = (memobj_t*)kmalloc(sizeof(memobj_t));
  if (!anon_obj) return 0x0;

  kmemset(anon_obj, 0, sizeof(memobj_t));

  anon_obj->type = MEMOBJ_ANON;
  anon_obj->id = fnv_hash_array(&anon_obj, sizeof(memobj_t*));
  anon_obj->ops = &g_anon_ops;
  anon_obj->refcount = 0;
  return anon_obj;
}
