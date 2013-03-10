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

// Basic slab allocator.  Best for objects < 128 bytes.
#ifndef APOO_MEMORY_SLAB_ALLOC_H
#define APOO_MEMORY_SLAB_ALLOC_H

struct slab_alloc;
typedef struct slab_alloc slab_alloc_t;

// Create a slab allocator to allocate regions for the given block size.
// block_size must be less than half a page.
//
// REQUIRES: kmalloc_init()
slab_alloc_t* slab_alloc_create(int obj_size, int max_pages);

// Destroy a slab allocator (and free all associated memory) created with
// slab_alloc_create.
void slab_alloc_destroy(slab_alloc_t* s);

// Allocate a block in the given slab allocator.
void* slab_alloc(slab_alloc_t* s);

// Free the a block in the given slab allocator.  Must pass a pointer returned
// by a call to slab_alloc().
void slab_free(slab_alloc_t* s, void* x);

#endif
