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

#include <stdarg.h>
#include <stdint.h>

#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/page_alloc.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs.h"

void vfs_mode_test(void) {
  KTEST_SUITE_BEGIN("vfs mode test");

  // Things to test,
  // * read/write/exec file (owner matches but perm bit not set)
  // * read/write/exec file (group matches but perm bit not set)
  // * read/write/exec file (owner and group matches but perm bit not set)
  // * read/write/exec file (owner and group don't match and 'other' perm bit not set)
  // * as above, but for a directory
  // * opening a file with appropriate permissions but not on path
  // * opening a file with the requested mode not allowed.
  // * for each syscall, an appropriate representatitive operation
  // * that the superuser can do anything
}
