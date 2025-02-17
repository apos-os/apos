// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SANITIZERS_TSAN_TSAN_SYNC_H
#define APOO_SANITIZERS_TSAN_TSAN_SYNC_H

#include <stdbool.h>
#include <stdint.h>

#include "common/types.h"
#include "sanitizers/tsan/vector_clock.h"

// Dynamic synchronization object.  Used for synchronizing atomics, which are
// not known statically.
//
// There are restrictions on size and alignment of atomic accesses associated
// with sync objects that are more stringent than the underlying hardware or
// memory model.
typedef struct tsan_sync {
  addr_t addr;
  tsan_vc_t clock;
  struct tsan_sync* next;
} tsan_sync_t;

// Returns the sync object associated with the given address.  If one does not
// exist, and |create| is set, it is created and returned.
//
// We don't have to worry about lifetime, because the only way a sync object
// would be deleted after being returned while still in use would be if the
// application code concurrently accesses and frees the memory, which is a bug.
tsan_sync_t* tsan_sync_get(addr_t addr, size_t access_size, bool create);

// Frees all the sync objects associated with the given range of memory.
void tsan_sync_free(addr_t addr, size_t len);

#endif
