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
#include "kmalloc.h"
#include "slab_alloc.h"
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

void slab_alloc_test() {
  KTEST_BEGIN("slab_alloc test");
  do_slab_test(8, 1, 504);
  do_slab_test(16, 1, 254);
  do_slab_test(512, 1, 7);
  do_slab_test(1024, 1, 3);
  do_slab_test(8, 3, 504 * 3);
  do_slab_test(1024, 5, 15);
}
