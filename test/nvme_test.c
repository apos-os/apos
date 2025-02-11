// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "common/kprintf.h"
#include "common/kstring.h"
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "memory/kmalloc.h"
#include "test/block_dev_test.h"
#include "test/ktest.h"

void nvme_test(void) {
  block_dev_t** bds =
      (block_dev_t**)kmalloc(DEVICE_MAX_MINOR * sizeof(block_dev_t*));
  int count = 0;
  for (int i = 0; i < DEVICE_MAX_MINOR; ++i) {
    bds[count] = dev_get_block(kmakedev(DEVICE_MAJOR_NVME, i));
    if (bds[count]) ++count;
  }

  if (count == 0) {
    KTEST_SUITE_BEGIN("NVMe (no drives");
    KTEST_ADD_FAILURE("Cannot run NVMe tests, no NVMe drives connected\n");
  }

  for (int i = 0; i < count; ++i) {
    char buf[256];
    ksprintf(buf, "NVMe (drive %d)", i);
    KTEST_SUITE_BEGIN(buf);

    bd_standard_test(bds[i]);
  }

  KTEST_SUITE_BEGIN("NVMe multi-disk thread test");
  bd_thread_test(&bds[0], count, 10, 100);

  kfree(bds);
}
