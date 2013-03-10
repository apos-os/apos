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

struct memobj_ops;
typedef struct memobj_ops memobj_ops_t;

// Types of memory objects.
typedef enum {
  MEMOBJ_BLOCK_DEV = 1,
} memobj_type_t;

// A memobj_t is an in-memory object backed by another data source, such as a
// block device or filesystem, that can be used to back the block cache.
//
// Each memobj_t has an ID that must be unique within it's type and a set of
// operations for reading and writing to the backing store.
typedef struct {
  memobj_type_t type;
  uint32_t id;  // Must be globally unique!
  memobj_ops_t* ops;

  // Data specific to the type memory object.
  void* data;
} memobj_t;

// Operations that can be performed on a memory object.
struct memobj_ops {
  // Read the page at |offset| from the backing store into |buffer|, which will
  // be page-aligned and page-sized.
  //
  // Return 0 on success, or -errno on error.
  int (*read_page)(memobj_t* obj, int offset, void* buffer);

  // Write the data in |buffer|, which is page-aligned and page-sized, into the
  // page at |offset| in the backing store.
  //
  // Return 0 on success, or -errno on error.
  int (*write_page)(memobj_t* obj, int offset, const void* buffer);
};

#endif
