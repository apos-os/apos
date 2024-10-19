// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_MEMORY_ALLOCATOR_H
#define APOO_MEMORY_ALLOCATOR_H

#include "common/attributes.h"
#include "common/types.h"

typedef struct {
  void* (*alloc)(void* arg, size_t n, size_t alignment);
  void (*free)(void* arg, void* ptr);
  void* arg;
} allocator_t;

// Static initializer for an (invalid) allocator_t.
#define ALLOCATOR_INIT_STATIC \
  { NULL, NULL, NULL }

static inline ALWAYS_INLINE void* alloc_alloc(const allocator_t* alloc,
                                              size_t n, size_t alignment) {
  return alloc->alloc(alloc->arg, n, alignment);
}

static inline ALWAYS_INLINE void alloc_free(const allocator_t* alloc,
                                            void* ptr) {
  return alloc->free(alloc->arg, ptr);
}

#endif
