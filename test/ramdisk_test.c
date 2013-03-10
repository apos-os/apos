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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/memory.h"
#include "test/block_dev_test.h"
#include "test/ktest.h"

void ramdisk_test() {
  KTEST_SUITE_BEGIN("ramdisk");
  ramdisk_t* rd;
  block_dev_t bd;
  KASSERT(ramdisk_create(10 * PAGE_SIZE, &rd) == 0);
  ramdisk_dev(rd, &bd);

  bd_standard_test(&bd);
  block_dev_t* bds = &bd;
  bd_thread_test(&bds, 1, 10, 5);

  ramdisk_destroy(rd);
}
