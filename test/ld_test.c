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

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/ld.h"
#include "test/ktest.h"

static ld_t* g_ld = 0;

static int g_sink_idx = 0;
static char g_sink[1024];
static void test_sink(void* arg, char c) {
  g_sink[g_sink_idx++] = c;
}

static void reset_sink() {
  g_sink_idx = 0;
}

static void echo_test() {
  KTEST_BEGIN("echo test");
  reset_sink();

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\b');

  KEXPECT_EQ(4, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
  KEXPECT_EQ('c', g_sink[2]);
  KEXPECT_EQ('\b', g_sink[3]);
}

static void provide_sink_test() {
  KTEST_BEGIN("ld_provide_sink() test");
  reset_sink();

  ld_provide_sink((void*)g_ld, 'a');
  ld_provide_sink((void*)g_ld, 'b');

  KEXPECT_EQ(2, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
}

static void write_test() {
  KTEST_BEGIN("ld_write() test");
  reset_sink();

  char buf[100];
  kstrcpy(buf, "hello, world");
  int write_len = ld_write(g_ld, buf, kstrlen(buf));

  KEXPECT_EQ(12, write_len);
  KEXPECT_EQ(12, g_sink_idx);
  KEXPECT_EQ(0, kstrncmp(g_sink, "hello, world", 12));

  // Make sure the 'n' parameter is respected.
  kstrcpy(buf, "ABCDEF");
  write_len = ld_write(g_ld, buf, 3);

  KEXPECT_EQ(3, write_len);
  KEXPECT_EQ(15, g_sink_idx);
  KEXPECT_EQ(0, kstrncmp(g_sink, "hello, worldABC", 15));
}

void ld_test() {
  KTEST_SUITE_BEGIN("line discipline");
  g_ld = ld_create();
  KASSERT(g_ld);

  ld_set_sink(g_ld, &test_sink, 0x0);

  echo_test();
  provide_sink_test();
  write_test();
}
