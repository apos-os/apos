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

// Internal of the kmalloc implementation.  Exposed here for testing.  Should
// not be used directly.
#ifndef APOO_MEMORY_KMALLOC_INTERNAL_H
#define APOO_MEMORY_KMALLOC_INTERNAL_H

#include <stdbool.h>

#include "common/config.h"
#include "common/stack_trace_table.h"
#include "common/types.h"

// Don't bother splitting a block if it'll be smaller than this (bytes).
#define KALLOC_MIN_BLOCK_SIZE 8

#define KALLOC_MAGIC 0xAB
#define KMALLOC_SAFE_BUFFER 16

// Every memory block has the following structure:
// | free (8 bits) | length (32 bits) | prev (32 bits) | next (32 bits) | data (length bytes) |
// That is, a header with the block length (not including the header), a pointer
// to the next block in chain, and then the data.
//
// In general, blocks are passed around by pointers to the start of their
// headers.  When we give a block to (or take on from) a caller, we use a
// pointer to the data.
struct block {
  uint8_t magic;
  bool free;
#if ENABLE_KMALLOC_HEAP_PROFILE
  trace_id_t stack_trace;
#endif
  addrdiff_t length;
  struct block* prev;
  struct block* next;
  uint8_t _buf[KMALLOC_SAFE_BUFFER];
  uint8_t data[0];
  // TODO(aoates): update kmalloc to always align block_t so we don't need to
  // mark it as packed.
} __attribute__((packed));
typedef struct block block_t;

// Returns the address (as an addr_t) of the start/end of the block_t,
// including header and data.
#define BLOCK_START(b) ((addr_t)b)
#define BLOCK_END(b) ((addr_t)b + sizeof(block_t) + b->length)

// Returns the total size of a block_t, including headers and data.
#define BLOCK_SIZE(b) (sizeof(block_t) + b->length)

// Not thread or interrupt-safe --- for tests only.
block_t* kmalloc_internal_get_block_list(void);

#endif
