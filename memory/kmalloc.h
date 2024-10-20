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

#ifndef APOO_MEMORY_KMALLOC_H
#define APOO_MEMORY_KMALLOC_H

#include <stddef.h>

#include "memory/allocator.h"

// TODO(aoates): document these
void kmalloc_init(void);
void kfree(void* x);
void* kmalloc(size_t n);
void* kmalloc_alloc(void* arg, size_t n, size_t alignment);
#define kmalloc_aligned(n, alignment) kmalloc_alloc(NULL, (n), (alignment))
void kmalloc_log_state(void);
void kmalloc_log_heap_profile(void);

// Enable test mode.  In test mode, certain components are not re-initialized in
// kmalloc_init(), allowing it to be called more than once.
//
// Once test mode is entered, the kernel is pretty much hosed and shouldn't be
// used (other than running the tests).
void kmalloc_enable_test_mode(void);

#define KMALLOC(_TYPE) ((_TYPE*)kmalloc(sizeof(_TYPE)));

// Default kmalloc-based allocator.
extern allocator_t kDefaultAlloc;

#endif
