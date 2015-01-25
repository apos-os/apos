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

#include "common/ascii.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/ld.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "test/ktest.h"
#include "user/include/apos/termios.h"

#define LD_BUF_SIZE 15

static ld_t* g_ld = 0;

static int g_sink_idx = 0;
static char g_sink[1024];
static void test_sink(void* arg, char c) {
  g_sink[g_sink_idx++] = c;
}

static void reset(void) {
  if (g_ld) {
    ld_destroy(g_ld);
  }

  g_ld = ld_create(LD_BUF_SIZE);
  KASSERT(g_ld);

  g_sink_idx = 0;
  ld_set_sink(g_ld, &test_sink, 0x0);
}

static void echo_test(void) {
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

static void provide_sink_test(void) {
  KTEST_BEGIN("ld_provide_sink() test");
  reset();

  ld_provide_sink((void*)g_ld, 'a');
  ld_provide_sink((void*)g_ld, 'b');

  KEXPECT_EQ(2, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
}

static void write_test(void) {
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

static void basic_read_test(void) {
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

static void eof_read_test(void) {
  KTEST_BEGIN("EOF ld_read() test");
  reset();

  char buf[100];
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(0, read_len);

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, ASCII_EOT);
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(3, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abc", 3));
}

static void cook_test(void) {
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

static void cook_limit_test(void) {
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

static void cook_limit_test2(void) {
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

// Sends too many chars then verifies that overloading worked correctly.
static void do_overload_test(void) {
  for (int i = 0; i < 26; i++) {
    ld_provide(g_ld, 'a' + i);
  }
  ld_provide(g_ld, '\n');

  // We should have exceeded the limit, so the newline was dropped.
  char buf[100];
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(0, read_len);

  // Make room then try cooking again.
  ld_provide(g_ld, '\b');
  ld_provide(g_ld, '\n');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(14, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abcdefghijklm\n", 14));
}

static void char_limit_test(void) {
  KTEST_BEGIN("buffer length limit test");
  reset();
  do_overload_test();

  // Now make sure we handle the limit in the middle of the buffer as well (when
  // wrapping).
  reset();
  for (int i = 0; i < 5; i++) {
    ld_provide(g_ld, 'a' + i);
  }
  char buf[100];
  ld_provide(g_ld, '\n');
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(6, read_len);

  // Now we should be in the middle of the buffer.  Try overloading again.
  do_overload_test();
}

static void wrap_deletes_test(void) {
  KTEST_BEGIN("wrap deletes around buffer test");
  reset();

  for (int i = 0; i < 10; i++) {
    ld_provide(g_ld, 'a' + i);
  }
  char buf[100];
  ld_provide(g_ld, '\n');
  int read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(11, read_len);

  for (int i = 0; i < 10; i++) {
    ld_provide(g_ld, 'a' + i);
  }
  for (int i = 0; i < 8; i++) {
    ld_provide(g_ld, '\b');
  }
  for (int i = 0; i < 6; i++) {
    ld_provide(g_ld, 'C' + i);
  }

  ld_provide(g_ld, '\n');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(9, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abCDEFGH\n", 9));
}

static void read_limit_test(void) {
  KTEST_BEGIN("ld_read() limit");
  reset();

  for (int i = 0; i < 10; i++) {
    ld_provide(g_ld, 'a' + i);
  }
  ld_provide(g_ld, '\n');

  // Read it in several chunks.
  char buf[100];
  int read_len = ld_read_async(g_ld, buf, 3);
  KEXPECT_EQ(3, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "abc", 3));

  read_len = ld_read_async(g_ld, buf, 4);
  KEXPECT_EQ(4, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "defg", 4));

  read_len = ld_read_async(g_ld, buf, 3);
  KEXPECT_EQ(3, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "hij", 3));

  read_len = ld_read_async(g_ld, buf, 1);
  KEXPECT_EQ(1, read_len);
  KEXPECT_EQ(0, kstrncmp(buf, "\n", 1));

  read_len = ld_read_async(g_ld, buf, 1);
  KEXPECT_EQ(0, read_len);
}

typedef struct {
  ld_t* l;
  int idx;
  int len;
  int out_len;
  char buf[100];
} read_test_data_t;

static void* basic_read_test_func(void* arg) {
  read_test_data_t* d = (read_test_data_t*)arg;
  KLOG("ld_read() thread %d started\n", d->idx);
  d->out_len = ld_read(d->l, d->buf, d->len);
  KLOG("ld_read() thread %d read %d bytes\n", d->idx, d->out_len);
  return 0;
}

static void basic_read_thread_test(void) {
  KTEST_BEGIN("basic read thread test");
  read_test_data_t data;
  data.l = g_ld;
  data.len = 100;
  data.idx = 0;
  data.out_len = 0;

  kthread_t thread;
  kthread_create(&thread, &basic_read_test_func, &data);
  scheduler_make_runnable(thread);

  scheduler_yield();

  // Write to the ld.
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');

  // Yield and make sure nothing was read yet.
  scheduler_yield();

  KEXPECT_EQ(0, data.out_len);
  ld_provide(g_ld, '\n');

  scheduler_yield();
  KEXPECT_EQ(4, data.out_len);
  KEXPECT_EQ(0, kstrncmp(data.buf, "abc\n", 4));

  kthread_join(thread);
}

static void three_thread_test(void) {
  KTEST_BEGIN("3-read thread test");
  read_test_data_t data[3];
  for (int i = 0; i < 3; ++i) {
    data[i].l = g_ld;
    data[i].idx = i;
    data[i].len = 1;
    data[i].out_len = 0;
  }

  kthread_t threads[3];
  for (int i = 0; i < 3; ++i) {
    kthread_create(&threads[i], &basic_read_test_func, &data[i]);
    scheduler_make_runnable(threads[i]);
  }

  scheduler_yield();

  // Write to the ld.
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');

  // Yield and make sure nothing was read yet.
  scheduler_yield();

  KEXPECT_EQ(0, data[0].out_len);
  KEXPECT_EQ(0, data[1].out_len);
  KEXPECT_EQ(0, data[2].out_len);
  ld_provide(g_ld, '\n');

  kthread_join(threads[0]);
  kthread_join(threads[1]);
  kthread_join(threads[2]);

  KEXPECT_EQ(1, data[0].out_len);
  KEXPECT_EQ(0, kstrncmp(data[0].buf, "a", 1));

  KEXPECT_EQ(1, data[1].out_len);
  KEXPECT_EQ(0, kstrncmp(data[1].buf, "b", 1));

  KEXPECT_EQ(1, data[2].out_len);
  KEXPECT_EQ(0, kstrncmp(data[2].buf, "c", 1));

  char buf[10];
  int read_len = ld_read(g_ld, buf, 10);
  KEXPECT_EQ(1, read_len);
}

// Same as above, but the first 2 threads consume all the available bytes.
static void three_thread_test2(void) {
  KTEST_BEGIN("3-read thread test #2");
  read_test_data_t data[3];
  for (int i = 0; i < 3; ++i) {
    data[i].l = g_ld;
    data[i].idx = i;
    data[i].len = 2;
    data[i].out_len = 0;
  }

  kthread_t threads[3];
  for (int i = 0; i < 3; ++i) {
    kthread_create(&threads[i], &basic_read_test_func, &data[i]);
    scheduler_make_runnable(threads[i]);
  }

  scheduler_yield();

  // Write to the ld.
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');

  // Yield and make sure nothing was read yet.
  scheduler_yield();

  KEXPECT_EQ(0, data[0].out_len);
  KEXPECT_EQ(0, data[1].out_len);
  KEXPECT_EQ(0, data[2].out_len);
  ld_provide(g_ld, '\n');

  kthread_join(threads[0]);
  kthread_join(threads[1]);

  KEXPECT_EQ(2, data[0].out_len);
  KEXPECT_EQ(0, kstrncmp(data[0].buf, "ab", 2));

  KEXPECT_EQ(2, data[1].out_len);
  KEXPECT_EQ(0, kstrncmp(data[1].buf, "c\n", 2));

  KEXPECT_EQ(0, data[2].out_len);

  ld_provide(g_ld, 'd');
  ld_provide(g_ld, '\n');
  kthread_join(threads[2]);

  // TODO(aoates): fix this to differentiate between empty-buffer EOF (which
  // *should* wake up all threads) and '\n' which is read by one thread, which
  // *shouldn't* cause all outstanding read()s to return.
  //KEXPECT_EQ(2, data[2].out_len);
  //KEXPECT_EQ(0, kstrncmp(data[2].buf, "d\n", 2));
}

static void termios_test(void) {
  KTEST_BEGIN("ld: default termios settings are sane");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  KEXPECT_EQ(0, t.c_iflag);
  KEXPECT_EQ(0, t.c_oflag);
  KEXPECT_EQ(CS8, t.c_cflag);
  KEXPECT_EQ(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG, t.c_lflag);
}

// TODO(aoates): more tests to write:
//  1) interrupt-masking test (provide() from a timer interrupt and
//  simultaneously read).

void ld_test(void) {
  KTEST_SUITE_BEGIN("line discipline");

  echo_test();
  provide_sink_test();
  write_test();
  basic_read_test();
  eof_read_test();
  cook_test();
  cook_limit_test();
  cook_limit_test2();
  char_limit_test();
  wrap_deletes_test();
  read_limit_test();
  basic_read_thread_test();
  three_thread_test();
  three_thread_test2();
  termios_test();

  ld_destroy(g_ld);
  g_ld = NULL;
}
