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

// A basic hash table for use in various kernel systems.  The key passed in is
// hashed again before internal use.
//
// This is a pretty crappy hashtable.  It doesn't resize, the hash function
// isn't great, and it's not really optimized.
// TODO(aoates): make this much better.
#ifndef APOO_HASHTABLE_H
#define APOO_HASHTABLE_H

#include <stdbool.h>
#include <stdint.h>

#include "memory/allocator.h"

typedef uint64_t htbl_key_t;

struct htbl_entry;
typedef struct htbl_entry htbl_entry_t;

struct htbl;
typedef struct htbl htbl_t;

// Initialize a hash table with a certain number of buckets.
void htbl_init(htbl_t* tbl, int buckets);

// As above, but uses a custom allocator for the hashtable.
void htbl_init_alloc(htbl_t* tbl, int buckets, const allocator_t* alloc);

// Clean up the memory used by the table.  You must still call kfree() on the
// htbl_t if you allocated it on the heap.
void htbl_cleanup(htbl_t* tbl);

// Puts the given value into the table, replacing any previous value for that
// key.
void htbl_put(htbl_t* tbl, htbl_key_t key, void* value);

// Retrieves the value stored for that key, returning 0 if successful.  Returns
// non-zero if the key couldn't be found.
int htbl_get(const htbl_t* tbl, htbl_key_t key, void** value);

// Removes the value associated with a given key, returning 0 if successful.
int htbl_remove(htbl_t* tbl, htbl_key_t key);

// Invoke func on each (key, value) pair in the table.  func is invoked with
// arg, the key, and the value, in that order.  There are no guarantees about
// what order the items will be iterated in, and func must not mutate the table.
// Equivalent to htbl_filter() and always returning false.
void htbl_iterate(const htbl_t* tbl, void (*func)(void*, htbl_key_t, void*),
                  void* arg);

// Clears (empties) the hash table, running the given function for each entry
// before it is removed.  The function should not mutate the table.
// Equivalent to htbl_filter() and always returning true.
void htbl_clear(htbl_t* tbl, void (*dtor)(void*, htbl_key_t, void*), void* arg);

// Runs the given function over the hashtable.  If it returns false, the entry
// is removed.  Returns the number of entries removed.
int htbl_filter(htbl_t* tbl, bool (*pred)(void*, htbl_key_t, void*), void* arg);

// Force a resize (for testing, most likely).
void htbl_resize(htbl_t* tbl, int num_buckets);

// Return the number of entries in the hashtable.
int htbl_size(const htbl_t* tbl);

// Return the number of buckets in the hashtable.
int htbl_num_buckets(const htbl_t* tbl);

// Internal definition.
struct htbl {
  const allocator_t* alloc;
  htbl_entry_t** buckets;
  int num_buckets;
  int num_entries;
};

// A static initializer for htbl_t --- the hashtable must still be initialized
// with htbl_init(), this is just a placeholder.
#define HTBL_STATIC_DECL { NULL, NULL, 0, 0 }

#endif
