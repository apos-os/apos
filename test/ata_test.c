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
#include "common/kprintf.h"
#include "dev/block.h"
#include "dev/ata/ata.h"
#include "kmalloc.h"
#include "test/block_dev_test.h"
#include "test/ktest.h"

void ata_test() {
  block_dev_t** bds = (block_dev_t**)kmalloc(
      ata_num_devices() * sizeof(block_dev_t*));
  for (int i = 0; i < ata_num_devices(); ++i) {
    bds[i] = ata_get_block_dev(i);
  }

  for (int i = 0; i < ata_num_devices(); ++i) {
    char buf[256];
    ksprintf(buf, "ATA (drive %d)", i);
    KTEST_SUITE_BEGIN(buf);

    bd_standard_test(bds[i]);
  }

  KTEST_SUITE_BEGIN("ATA multi-disk thread test");
  bd_thread_test(&bds[0], ata_num_devices(), 2, 2);

  kfree(bds);
}
