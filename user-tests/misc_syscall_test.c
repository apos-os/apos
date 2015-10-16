// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include <apos/syscall_decls.h>
#include <apos/time_types.h>

#include "ktest.h"

void misc_syscall_test(void) {
  KTEST_SUITE_BEGIN("apos_get_time() test");
  KTEST_BEGIN("apos_get_time(): basic test");
  struct apos_tm tm;
  memset(&tm, 0, sizeof(tm));

  KEXPECT_EQ(0, apos_get_time(&tm));
  KEXPECT_GE(tm.tm_year, 2015 - 1900);
  KEXPECT_LE(tm.tm_year, 3000 - 1900);
  KEXPECT_GE(tm.tm_mon, 0);
  KEXPECT_LE(tm.tm_mon, 11);
  KEXPECT_GE(tm.tm_mday, 1);
  KEXPECT_LE(tm.tm_mday, 31);
  KEXPECT_GE(tm.tm_hour, 0);
  KEXPECT_LE(tm.tm_hour, 23);
  KEXPECT_GE(tm.tm_min, 0);
  KEXPECT_LE(tm.tm_min, 59);
  KEXPECT_GE(tm.tm_sec, 0);
  KEXPECT_LE(tm.tm_sec, 61);

  KTEST_BEGIN("apos_get_time(): bad arguments test");
  KEXPECT_EQ(-1, apos_get_time(NULL));
  KEXPECT_EQ(EFAULT, errno);
  KEXPECT_EQ(-1, apos_get_time((struct apos_tm*)0x1cfff));
  KEXPECT_EQ(-1, apos_get_time((struct apos_tm*)0xc1000000));
}
