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
#include "dev/block.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory.h"
#include "test/ktest.h"

// TODO(aoates): make this a standard test suite for block devices.
static void block_test(block_dev_t* bd) {
  KTEST_BEGIN("block device test");
  KEXPECT_EQ(bd->sector_size, 512);
  KEXPECT_EQ(bd->sectors, 80);

  KTEST_BEGIN("non-aligned parameters");
  char buf[1024];
  KEXPECT_EQ(-EINVAL, bd->read(bd, 0, buf, 768));
  KEXPECT_EQ(-EINVAL, bd->write(bd, 0, buf, 768));

  kmemset(buf, 1, 256);
  kmemset(buf + 256, 2, 256);
  kmemset(buf + 512, 3, 256);
  kmemset(buf + 768, 3, 256);

  char golden_buf[1024];
  kmemcpy(golden_buf, buf, 1024);

  KTEST_BEGIN("write() then read()");
  KEXPECT_EQ(1024, bd->write(bd, 5, buf, 1024));
  kmemset(buf, 0, 1024);

  KEXPECT_EQ(1024, bd->read(bd, 5, buf, 1024));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 1024));

  KTEST_BEGIN("small read()");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(512, bd->read(bd, 5, buf, 512));
  KEXPECT_NE(0, kmemcmp(buf, golden_buf, 1024));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));

  KTEST_BEGIN("past-end-of-file read()");
  KEXPECT_EQ(0, bd->read(bd, bd->sectors + 1, buf, 1024));

  KTEST_BEGIN("past-end-of-file write()");
  KEXPECT_EQ(0, bd->write(bd, bd->sectors + 1, buf, 1024));

  KTEST_BEGIN("runs past-end-of-file write()");
  KEXPECT_EQ(512, bd->write(bd, bd->sectors - 1, golden_buf, 1024));

  KTEST_BEGIN("runs past-end-of-file read()");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(512, bd->read(bd, bd->sectors - 1, buf, 1024));
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));

  KTEST_BEGIN("overlapping write()s");
  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->write(bd, 5, golden_buf, 1024));
  KEXPECT_EQ(1024, bd->write(bd, 6, golden_buf, 1024));

  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->read(bd, 5, buf, 1024));
  // Should be the first and second 256-byte blocks repeated twice.
  KEXPECT_EQ(0, kmemcmp(buf, golden_buf, 512));
  KEXPECT_EQ(0, kmemcmp(buf + 512, golden_buf, 512));

  KTEST_BEGIN("multi write() then read() test");
  kmemset(buf, 1, 1024);
  KEXPECT_EQ(512, bd->write(bd, 0, buf, 512));
  kmemset(buf, 2, 1024);
  KEXPECT_EQ(512, bd->write(bd, 1, buf, 512));

  kmemset(buf, 0, 1024);
  KEXPECT_EQ(1024, bd->read(bd, 0, buf, 1024));

  char golden2[1024];
  kmemset(golden2, 1, 512);
  kmemset(golden2 + 512, 2, 512);
  KEXPECT_EQ(0, kmemcmp(buf, golden2, 1024));
}

void ramdisk_test() {
  KTEST_SUITE_BEGIN("ramdisk");
  ramdisk_t* rd;
  block_dev_t bd;
  KASSERT(ramdisk_create(10 * PAGE_SIZE, &rd) == 0);
  ramdisk_dev(rd, &bd);

  block_test(&bd);

  ramdisk_destroy(rd);
}
