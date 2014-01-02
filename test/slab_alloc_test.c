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

#include <stdint.h>

#include "common/debug.h"
#include "common/kassert.h"
#include "common/hash.h"
#include "memory/kmalloc.h"
#include "memory/slab_alloc.h"
#include "test/ktest.h"

// Make a slab allocator and ensure we can allocate the expected number of
// objects.
static void do_slab_test(int obj_size, int max_pages, int expected_objs) {
  slab_alloc_t* s = slab_alloc_create(obj_size, max_pages);

  void** ptrs = (void**)kmalloc(sizeof(void*) * expected_objs);

  // Do 2 cycles of alloc and free.
  for (int i = 0; i < 2; ++i) {
    int count = 0;
    while (count < expected_objs) {
      ptrs[count] = slab_alloc(s);
      if (!ptrs[count]) {
        break;
      }
      kmemset(ptrs[count], count % 256, obj_size);
      count++;
    }
    KEXPECT_EQ(expected_objs, count);

    while (count) {
      --count;
      for (int idx = 0; idx < obj_size; idx++) {
        if (((uint8_t*)ptrs[count])[idx] != count % 256) {
          KEXPECT_EQ(((uint8_t*)ptrs[count])[idx], count % 256);
        }
      }
      slab_free(s, ptrs[count]);
    }
  }

  kfree(ptrs);
  slab_alloc_destroy(s);
}

// Similar to the above, but do partial allocations and deallocations in random
// order.
static void random_slab_test(int obj_size, int max_pages, int expected_objs) {
  uint32_t rand = 12345;
  rand = fnv_hash_concat(rand, obj_size);
  rand = fnv_hash_concat(rand, max_pages);
  rand = fnv_hash_concat(rand, expected_objs);

  slab_alloc_t* s = slab_alloc_create(obj_size, max_pages);

  void** ptrs = (void**)kmalloc(sizeof(void*) * expected_objs);

  for (int i = 0; i < expected_objs; ++i) {
    ptrs[i] = slab_alloc(s);
  }

  KEXPECT_EQ((void*)0x0, slab_alloc(s));

  // Shuffle the pointers.
  for (int i = 0; i < expected_objs; i++) {
    rand = fnv_hash_concat(rand, i);
    //int swap_idx = rand % expected_objs;

    //void* A = ptrs[i];
    //ptrs[i] = ptrs[swap_idx];
    //ptrs[swap_idx] = A;
  }

  // Free half the items.
  for (int i = 0; i < expected_objs / 2; ++i) {
    if (ptrs[i]) {
      slab_free(s, ptrs[i]);
      ptrs[i] = 0x0;
    }
  }

  // ...then reallocate them.
  for (int i = 0; i < expected_objs / 2; ++i) {
    ptrs[i] = slab_alloc(s);
    if (!ptrs[i]) {
      KEXPECT_NE((void*)0x0, ptrs[i]);
    }
  }

  KEXPECT_EQ((void*)0x0, slab_alloc(s));

  // ...then free again.
  for (int i = 0; i < expected_objs / 2; ++i) {
    if (ptrs[i]) {
      slab_free(s, ptrs[i]);
      ptrs[i] = 0x0;
    }
  }

  kfree(ptrs);
  slab_alloc_destroy(s);
}

// Test allocating all items, then deallocating one early and one late in the
// memory order, then reallocating it and ensuring the page-full bits are kept
// consistent.
static void last_dealloc_test(void) {
  KTEST_BEGIN("alloc/dealloc smallest/largest");
  const int kMaxPtrs = 254;
  slab_alloc_t* s = slab_alloc_create(16, 1);
  void* ptrs[kMaxPtrs];

  void* smallest = 0x0, *largest = 0x0;;
  for (int i = 0; i < kMaxPtrs; ++i) {
    ptrs[i] = slab_alloc(s);
    if (!smallest || smallest < ptrs[i])
      smallest = ptrs[i];
    if (!largest || largest > ptrs[i])
      largest = ptrs[i];
  }

  // Free then re-alloc the smallest pointer.
  slab_free(s, smallest);
  smallest = slab_alloc(s);
  KEXPECT_EQ((void*)0x0, slab_alloc(s));

  // Free then re-alloc the largest pointer.
  slab_free(s, largest);
  largest = slab_alloc(s);
  KEXPECT_EQ((void*)0x0, slab_alloc(s));

  slab_alloc_destroy(s);
}

void slab_alloc_test(void) {
  KTEST_SUITE_BEGIN("slab_alloc test");
  KTEST_BEGIN("alloc test");
  do_slab_test(8, 1, 504);
  do_slab_test(16, 1, 254);
  do_slab_test(512, 1, 7);
  do_slab_test(1024, 1, 3);
  do_slab_test(8, 3, 504 * 3);
  do_slab_test(1024, 5, 15);

  KTEST_BEGIN("random dealloc test");
  random_slab_test(8, 1, 504);
  random_slab_test(16, 1, 254);
  random_slab_test(8, 3, 504 * 3);

  last_dealloc_test();
}
