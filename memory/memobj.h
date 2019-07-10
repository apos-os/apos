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

#ifndef APOO_MEMORY_MEMOBJ_H
#define APOO_MEMORY_MEMOBJ_H

#include <stdint.h>

#include "memory/block_cache.h"
#include "proc/spinlock.h"

struct memobj_ops;
typedef struct memobj_ops memobj_ops_t;

// Types of memory objects.
typedef enum {
  MEMOBJ_BLOCK_DEV = 1,
  MEMOBJ_VNODE = 2,
  MEMOBJ_SHADOW = 3,
  MEMOBJ_ANON = 4,
  MEMOBJ_FAKE = 5,
} memobj_type_t;

// A memobj_t is an in-memory object backed by another data source, such as a
// block device or filesystem, that can be used to back the block cache.
//
// Each memobj_t has an ID that must be unique within it's type and a set of
// operations for reading and writing to the backing store.
typedef struct memobj {
  memobj_type_t type;
  uint32_t id;  // Must be globally unique!
  memobj_ops_t* ops;

  // Refcount.  Do not modify directly --- use ref() and unref() instead.  The
  // meaning may very depending on the memobj type.
  // TODO(aoates): switch this to use appropriate atomics.
  int refcount;
  kspinlock_t lock;

  // Data specific to the type memory object.
  void* data;
} memobj_t;

// Operations that can be performed on a memory object.
struct memobj_ops {
  // Ref or unref the given memobj.  This may modify refcounts on underlying
  // back store objects as well.  The caller to unref must not access the
  // memobj_t after unref() returns, unless it has another reference.
  void (*ref)(memobj_t* obj);
  void (*unref)(memobj_t* obj);

  // ********************************* VM ops **********************************
  // The following operations are for use by the VM system.  They should be used
  // instead of the corresponding functions directly on the block_cache, as the
  // memobj (in particular, shadow objects) may impose additional behavior.
  // ***************************************************************************

  // Get a page entry from the memobj, allocating a page frame and reading the
  // data from the backing store if necessary.  The page is returned with a pin
  // put in it.  The caller must call put_page() later to unpin it.
  //
  // If writable is zero, then the returned page *may belong to another memobj*,
  // and MUST NOT be modified.
  //
  // Returns 0 on success, or -errno on error.
  int (*get_page)(memobj_t* obj, int page_offset, int writable,
                  bc_entry_t** entry_out);

  // Unpin a page retrieved with get_page() above.  The caller must not refer to
  // the bc_entry_t after this call unless it has another pinned copy.
  //
  // Note: if get_page() returned a bc_entry_t belonging to a different
  // memobj_t, then put_page() should supply the *original* memobj_t, not the
  // one owning the bc_entry_t.
  //
  // Returns 0 on success, or -errno on error.
  int (*put_page)(memobj_t* obj, bc_entry_t* entry,
                  block_cache_flush_t flush_mode);


  // **************************** block cache ops ******************************
  // The following operations are for use by the block cache code for paging
  // data in and out of the backing store.  Other clients (such as filesystems
  // and VM) should use the get/lookup/put functions above.
  // ***************************************************************************

  // Read the page at |page_offset| (which is in pages, not bytes) from the
  // backing store into |buffer|, which will be page-aligned and page-sized.
  //
  // Return 0 on success, or -errno on error.
  int (*read_page)(memobj_t* obj, int page_offset, void* buffer);

  // Write the data in |buffer|, which is page-aligned and page-sized, into the
  // page at |page_offset| (which is in pages, not bytes) in the backing store.
  //
  // Return 0 on success, or -errno on error.
  int (*write_page)(memobj_t* obj, int page_offset, const void* buffer);
};

#endif
