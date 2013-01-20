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

// A basic hash table for use in various kernel systems.
//
// This is a pretty crappy hashtable.  It doesn't resize, the hash function
// isn't create, and it's not really optimized.
// TODO(aoates): make this much better.
#ifndef APOO_HASHTABLE_H
#define APOO_HASHTABLE_H

#include <stdint.h>

struct htbl_entry;
typedef struct htbl_entry htbl_entry_t;

struct htbl {
  htbl_entry_t** buckets;
  int num_buckets;
};
typedef struct htbl htbl_t;

// Initialize a hash table with a certain number of buckets.
void htbl_init(htbl_t* tbl, int buckets);

// Clean up the memory used by the table.  You must still call kfree() on the
// htbl_t if you allocated it on the heap.
void htbl_cleanup(htbl_t* tbl);

// Puts the given value into the table, replacing any previous value for that
// key.
void htbl_put(htbl_t* tbl, uint32_t key, void* value);

// Retrieves the value stored for that key, returning 0 if successful.  Returns
// non-zero if the key couldn't be found.
int htbl_get(htbl_t* tbl, uint32_t key, void** value);

// Removes the value associated with a given key, returning 0 if successful.
int htbl_remove(htbl_t* tbl, uint32_t key);

// Invoke func on each (key, value) pair in the table.  func is invoked with
// arg, the key, and the value, in that order.  There are no guarantees about
// what order the items will be iterated in, and func must not mutate the table.
void htbl_iterate(htbl_t* tbl, void (*func)(void*, uint32_t, void*), void* arg);

#endif
