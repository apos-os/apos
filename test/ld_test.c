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
#include "kmalloc.h"
#include "test/ktest.h"

static ld_t* g_ld = 0;

static int g_sink_idx = 0;
static char g_sink[1024];
static void test_sink(void* arg, char c) {
  g_sink[g_sink_idx++] = c;
}

static void reset() {
  if (g_ld) {
    kfree(g_ld);
  }

  g_ld = ld_create();
  KASSERT(g_ld);

  g_sink_idx = 0;
  ld_set_sink(g_ld, &test_sink, 0x0);
}

static void echo_test() {
  KTEST_BEGIN("echo test");
  reset();

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
  reset();

  ld_provide_sink((void*)g_ld, 'a');
  ld_provide_sink((void*)g_ld, 'b');

  KEXPECT_EQ(2, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
}

static void write_test() {
  KTEST_BEGIN("ld_write() test");
  reset();

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

static void basic_read_test() {
  KTEST_BEGIN("basic ld_read() test");
  reset();

  char buf[100];
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(0, read_len);

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\n');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(4, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abc\n", 4));
}

static void cook_test() {
  KTEST_BEGIN("ld_read() cooking test");
  reset();

  char buf[100];
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(0, read_len);

  // Delete some chars then provide new ones.
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, 'D');
  ld_provide(g_ld, 'E');
  ld_provide(g_ld, 'F');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(0, read_len);

  ld_provide(g_ld, '\n');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(5, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "aDEF\n", 5));
}

static void cook_limit_test() {
  KTEST_BEGIN("ld_read() cook-past-start-of-line test");
  reset();

  char buf[100];
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\n');

  ld_provide(g_ld, 'd');
  ld_provide(g_ld, 'e');
  ld_provide(g_ld, 'f');

  // Delete too many chars.
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, 'g');
  ld_provide(g_ld, 'h');
  ld_provide(g_ld, '\n');

  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(7, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abc\ngh\n", 7));
}

static void cook_limit_test2() {
  KTEST_BEGIN("ld_read() cook-past-start-of-line test (start_idx in middle)");
  reset();

  char buf[100];
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\n');
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(4, read_len);

  ld_provide(g_ld, 'd');
  ld_provide(g_ld, 'e');
  ld_provide(g_ld, 'f');

  // Delete too many chars.
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, 'g');
  ld_provide(g_ld, 'h');
  ld_provide(g_ld, '\n');

  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(3, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "gh\n", 3));
}

// TODO(aoates): more tests to write:
//  1) blocking test with threads
//  2) dropping excees characters test
//  3) wrapping around end of buffer test (for start, cooked, and raw idxs).

void ld_test() {
  KTEST_SUITE_BEGIN("line discipline");

  echo_test();
  provide_sink_test();
  write_test();
  basic_read_test();
  cook_test();
  cook_limit_test();
  cook_limit_test2();
}
