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
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/ld.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "user/include/apos/termios.h"
#include "user/include/apos/vfs/vfs.h"

#define LD_BUF_SIZE 15

static ld_t* g_ld = 0;

static int g_sink_idx = 0;
static char g_sink[1024];
static void test_sink(void* arg, char c) {
  g_sink[g_sink_idx++] = c;
}

static void reset_sink(void) {
  g_sink_idx = 0;
  kmemset(g_sink, 0, 1024);
}

static void reset(void) {
  if (g_ld) {
    ld_destroy(g_ld);
  }

  g_ld = ld_create(LD_BUF_SIZE);
  KASSERT(g_ld);

  ld_set_sink(g_ld, &test_sink, 0x0);
  reset_sink();
}

static void ld_provides(ld_t* l, const char* s) {
  while (*s) ld_provide(l, *(s++));
}

static int ld_read_async(ld_t* l, char* buf, int n) {
  return ld_read(l, buf, n, VFS_O_NONBLOCK);
}

static void echo_test(void) {
  KTEST_BEGIN("echo test");
  reset();

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');

  KEXPECT_EQ(3, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
  KEXPECT_EQ('c', g_sink[2]);

  KTEST_BEGIN("echo backspace test");
  reset();
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(5, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);
  KEXPECT_EQ('b', g_sink[1]);
  KEXPECT_EQ('\b', g_sink[2]);
  KEXPECT_EQ(' ', g_sink[3]);
  KEXPECT_EQ('\b', g_sink[4]);
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
  KEXPECT_EQ(-EAGAIN, read_len);

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
  KEXPECT_EQ(-EAGAIN, read_len);

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
  KEXPECT_EQ(-EAGAIN, read_len);

  // Delete some chars then provide new ones.
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, 'D');
  ld_provide(g_ld, 'E');
  ld_provide(g_ld, 'F');
  read_len = ld_read_async(g_ld, buf, 100);
  KEXPECT_EQ(-EAGAIN, read_len);

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
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
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
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
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
  KEXPECT_EQ(-EAGAIN, read_len);

  // Make room then try cooking again.
  ld_provide(g_ld, '\x7f');
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
    ld_provide(g_ld, '\x7f');
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
  KEXPECT_EQ(-EAGAIN, read_len);
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
  d->out_len = ld_read(d->l, d->buf, d->len, 0);
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
  int read_len = ld_read(g_ld, buf, 10, 0);
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

  KEXPECT_EQ(-EAGAIN, data[2].out_len);

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
  const struct termios orig_term = t;

  KEXPECT_EQ(0, t.c_iflag);
  KEXPECT_EQ(0, t.c_oflag);
  KEXPECT_EQ(CS8, t.c_cflag);
  KEXPECT_EQ(ECHO | ECHOE | ECHOK | ICANON | ISIG, t.c_lflag);

  KTEST_BEGIN("ld: set invalid termios (c_iflag)");
  t.c_iflag |= ISTRIP;
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, TCSANOW, &t));

  KTEST_BEGIN("ld: set invalid termios (c_iflag)");
  t = orig_term;
  t.c_oflag |= OPOST;
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, TCSANOW, &t));

  KTEST_BEGIN("ld: set invalid termios (c_cflag)");
  t = orig_term;
  t.c_cflag = CS5 | CREAD;
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, TCSANOW, &t));

  KTEST_BEGIN("ld: set invalid termios (c_lflag)");
  t = orig_term;
  t.c_lflag |= IEXTEN;
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, TCSANOW, &t));
  t = orig_term;
  t.c_lflag |= (1 << 10);
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, TCSANOW, &t));

  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &orig_term));
}

static void termios_echo_test(void) {
  KTEST_BEGIN("ld: disable ECHO");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  const struct termios orig_term = t;

  ld_provide(g_ld, 'a');
  t.c_lflag &= ~ECHO;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\n');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(1, g_sink_idx);
  KEXPECT_EQ('a', g_sink[0]);

  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &orig_term));
}

typedef struct {
  kthread_queue_t read_started;
  bool read_done;
  char* buf;
  int readlen;
  ld_t* l;
  apos_ms_t elapsed;
} noncanon_test_args_t;

static void* noncanon_read(void* arg) {
  noncanon_test_args_t* args = arg;
  args->read_done = false;
  scheduler_wake_all(&args->read_started);
  apos_ms_t start = get_time_ms();
  int result = ld_read(args->l, args->buf, args->readlen, 0);
  args->elapsed = get_time_ms() - start;
  args->read_done = true;
  return (void*)result;
}

static void start_read_thread(noncanon_test_args_t* args, kthread_t* thread,
                              int read_len) {
  args->readlen = read_len;
  kmemset(args->buf, '\0', 10);
  KEXPECT_EQ(0, kthread_create(thread, &noncanon_read, args));
  scheduler_make_runnable(*thread);
  scheduler_wait_on(&args->read_started);
}

static void termios_noncanon_read_test(void) {
  KTEST_BEGIN("ld: non-canonical mode (MIN == 0, TIME == 0)");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  const struct termios orig_term = t;

  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 0;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(-EAGAIN, ld_read(g_ld, buf, 10, 0));
  // TODO(aoates): verify ld_read didn't block.
  KEXPECT_STREQ("", buf);

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ab", buf);
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, 'd');
  KEXPECT_EQ(1, ld_read(g_ld, buf, 1, 0));
  KEXPECT_EQ(1, ld_read(g_ld, buf, 1, 0));


  KTEST_BEGIN("ld: non-canonical mode (MIN > 0, TIME == 0)");
  t = orig_term;
  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 3;
  t.c_cc[VTIME] = 0;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  noncanon_test_args_t args;
  args.buf = buf;
  args.l = g_ld;
  kthread_queue_init(&args.read_started);
  kthread_t read_thread;

  kmemset(buf, 0, 10);
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  KEXPECT_EQ(3, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("abc", buf);

  // Test blocking behavior if fewer than MIN available.
  ld_provide(g_ld, 'd');
  ld_provide(g_ld, 'e');
  start_read_thread(&args, &read_thread, 10);
  ksleep(300);
  KEXPECT_EQ(false, args.read_done);
  ld_provide(g_ld, 'f');
  KEXPECT_EQ((void*)3, kthread_join(read_thread));
  KEXPECT_GE(args.elapsed, 300);
  KEXPECT_LE(args.elapsed, 400);
  KEXPECT_STREQ("def", buf);

  // Test signal interruptions in blocking scenario (no initial bytes).
  start_read_thread(&args, &read_thread, 10);
  scheduler_interrupt_thread(read_thread);
  KEXPECT_EQ((void*)(-EINTR), kthread_join(read_thread));

  // Test signal interruptions in blocking scenario (<MIN initial bytes).
  ld_provide(g_ld, 'd');
  ld_provide(g_ld, 'e');
  start_read_thread(&args, &read_thread, 10);
  scheduler_interrupt_thread(read_thread);
  KEXPECT_EQ((void*)(-EINTR), kthread_join(read_thread));
  t.c_cc[VMIN] = t.c_cc[VTIME] = 0;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));


  KTEST_BEGIN("ld: non-canonical mode (MIN == 0, TIME > 0)");
  t = orig_term;
  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 2;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  // Test when data never becomes available (ld_read times out).
  kmemset(buf, 0, 10);
  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(-EAGAIN, ld_read(g_ld, buf, 10, 0));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 150);
  KEXPECT_LE(end - start, 300);

  // Test when data is immediately available.
  ld_provide(g_ld, 'a');
  start = get_time_ms();
  // TODO(aoates): verify this doesn't block.
  KEXPECT_EQ(1, ld_read(g_ld, buf, 10, 0));
  end = get_time_ms();
  KEXPECT_LE(end - start, 30);

  // Test when data becomes available partway through TIME.
  start_read_thread(&args, &read_thread, 3);
  ksleep(100);
  KEXPECT_EQ(false, args.read_done);
  ld_provide(g_ld, 'f');
  KEXPECT_EQ((void*)1, kthread_join(read_thread));
  KEXPECT_GE(args.elapsed, 100);
  KEXPECT_LE(args.elapsed, 200);
  KEXPECT_STREQ("f", buf);

  // Test signal interruptions in blocking scenario.
  start_read_thread(&args, &read_thread, 10);
  scheduler_interrupt_thread(read_thread);
  KEXPECT_EQ((void*)(-EINTR), kthread_join(read_thread));


  KTEST_BEGIN("ld: non-canonical mode (MIN > 0, TIME > 0)");
  t = orig_term;
  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 4;
  t.c_cc[VTIME] = 2;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  // MIN bytes available initially.
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, 'd');
  start = get_time_ms();
  kmemset(buf, '\0', 10);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 10, 0));
  // TODO(aoates): verify ld_read didn't block.
  end = get_time_ms();
  KEXPECT_LE(end - start, 30);
  KEXPECT_STREQ("abcd", buf);

  // Fewer than MIN bytes available initially, times out after TIME.
  ld_provide(g_ld, 'e');
  ld_provide(g_ld, 'f');
  start = get_time_ms();
  kmemset(buf, '\0', 10);
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));
  end = get_time_ms();
  KEXPECT_GE(end - start, 180);
  KEXPECT_LE(end - start, 250);
  KEXPECT_STREQ("ef", buf);

  // 0 bytes available initially, blocks indefinitely, then MIN bytes.
  start_read_thread(&args, &read_thread, 5);
  ksleep(400);
  KEXPECT_EQ(false, args.read_done);
  ld_provide(g_ld, 'g');
  ld_provide(g_ld, 'h');
  ld_provide(g_ld, 'i');
  ksleep(50);
  ld_provide(g_ld, 'j');
  KEXPECT_EQ((void*)4, kthread_join(read_thread));
  KEXPECT_GE(args.elapsed, 430);
  KEXPECT_LE(args.elapsed, 500);
  KEXPECT_STREQ("ghij", buf);

  // 0 bytes initially, blocks, then < MIN bytes and timeout after TIME
  start_read_thread(&args, &read_thread, 5);
  ksleep(200);
  KEXPECT_EQ(false, args.read_done);
  ld_provide(g_ld, 'k');
  KEXPECT_EQ((void*)1, kthread_join(read_thread));
  KEXPECT_GE(args.elapsed, 380);
  KEXPECT_LE(args.elapsed, 450);
  KEXPECT_STREQ("k", buf);

  // Test signal interruptions in blocking scenario (no initial bytes).
  start_read_thread(&args, &read_thread, 10);
  scheduler_interrupt_thread(read_thread);
  KEXPECT_EQ((void*)(-EINTR), kthread_join(read_thread));

  // Test signal interruptions in blocking scenario (waiting for MIN bytes).
  ld_provide(g_ld, 'd');
  ld_provide(g_ld, 'e');
  start_read_thread(&args, &read_thread, 10);
  scheduler_interrupt_thread(read_thread);
  KEXPECT_EQ((void*)(-EINTR), kthread_join(read_thread));
  t.c_cc[VMIN] = t.c_cc[VTIME] = 0;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));

  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &orig_term));
}

static void control_chars_test(void) {
  KTEST_BEGIN("ld: echoing non-special control characters");
  reset();
  ld_provide(g_ld, 'x');
  ld_provide(g_ld, '\x01');
  ld_provide(g_ld, '\x02');
  ld_provide(g_ld, '\x08');

  KEXPECT_EQ(7, g_sink_idx);
  KEXPECT_STREQ("x^A^B^H", g_sink);

  ld_provide(g_ld, '\x04');
  char buf[50];
  kmemset(buf, 0, 50);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 50, 0));
  KEXPECT_STREQ("x\x01\x02\x08", buf);

  KTEST_BEGIN("ld: backspace over non-special control characters");
  reset();
  ld_provide(g_ld, 'x');
  ld_provide(g_ld, '\x08');
  ld_provide(g_ld, 'y');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(13, g_sink_idx);
  KEXPECT_STREQ("x^Hy\b \b\b \b\b \b", g_sink);

  ld_provide(g_ld, '\x04');
  kmemset(buf, 0, 50);
  KEXPECT_EQ(1, ld_read(g_ld, buf, 50, 0));
  KEXPECT_STREQ("x", buf);

  KTEST_BEGIN("ld: echoing space control characters");
  reset();
  ld_provide(g_ld, ' ');
  ld_provide(g_ld, '\n');
  ld_provide(g_ld, '\t');
  ld_provide(g_ld, '\v');

  KEXPECT_EQ(4, g_sink_idx);
  KEXPECT_STREQ(" \n\t\v", g_sink);

  ld_provide(g_ld, '\x04');
  kmemset(buf, 0, 50);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 50, 0));
  KEXPECT_STREQ(" \n\t\v", buf);

  KTEST_BEGIN("ld: backspace over space control characters");
  reset();
  ld_provide(g_ld, ' ');
  ld_provide(g_ld, '\t');
  ld_provide(g_ld, '\v');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(12, g_sink_idx);
  KEXPECT_STREQ(" \t\v\b \b\b \b\b \b", g_sink);

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, '\x04');
  KEXPECT_EQ(1, ld_read(g_ld, buf, 50, 0));

  KTEST_BEGIN("ld: signal-causing characters echoed");
  reset();
  ld_provide(g_ld, '\x03');
  ld_provide(g_ld, '\x1a');
  ld_provide(g_ld, '\x1c');
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, '\x04');

  KEXPECT_EQ(7, g_sink_idx);
  KEXPECT_STREQ("^C^Z^\\a", g_sink);

  // They shouldn't have been put in the buffer, since ISIG is set.
  KEXPECT_EQ(1, ld_read(g_ld, buf, 50, 0));
  KEXPECT_EQ('a', buf[0]);

  KTEST_BEGIN("ld: signal-causing characters discard current ld buffer");
  reset();
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x03');
  // TODO(aoates): test that an ld_read() here would block.
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x04');

  KEXPECT_EQ(5, g_sink_idx);
  KEXPECT_STREQ("ab^Cc", g_sink);

  KEXPECT_EQ(1, ld_read(g_ld, buf, 10, 0));
  KEXPECT_EQ('c', buf[0]);

  KTEST_BEGIN("ld: backspace over signal-causing characters");
  reset_sink();
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, '\x03');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(7, g_sink_idx);
  KEXPECT_STREQ("a^Cc\b \b", g_sink);
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));
}

static void noflsh_test(void) {
  KTEST_BEGIN("ld: NOFLSH prevents clearing buffer on INT, etc");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  const struct termios orig_term = t;

  t.c_lflag |= NOFLSH;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x03');
  ld_provide(g_ld, '\x1a');
  ld_provide(g_ld, '\x1c');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x04');

  KEXPECT_EQ(9, g_sink_idx);
  KEXPECT_STREQ("ab^C^Z^\\c", g_sink);

  char buf[10];
  KEXPECT_EQ(3, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("abc", buf);

  KTEST_BEGIN("ld: backspace over signal-causing characters with NOFLSH");
  reset_sink();
  ld_provide(g_ld, 'a');
  ld_provide(g_ld, '\x03');
  ld_provide(g_ld, '\x1a');
  ld_provide(g_ld, '\x1c');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\x7f');

  KEXPECT_EQ(14, g_sink_idx);
  KEXPECT_STREQ("a^C^Z^\\c\b \b\b \b", g_sink);
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));

  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &orig_term));
}

static void termios_noncanon_test(void) {
  KTEST_BEGIN("ld: <C-D> is printed in non-canonical mode");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  const struct termios orig_term = t;

  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 0;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, '\x04');
  KEXPECT_EQ(3, g_sink_idx);
  KEXPECT_STREQ("a^D", g_sink);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x04", buf);


  KTEST_BEGIN("ld: <backspace> is printed in non-canonical mode");
  reset_sink();
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, '\b');
  KEXPECT_EQ(5, g_sink_idx);
  KEXPECT_STREQ("b^?^H", g_sink);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("b\x7f\b", buf);

  ld_set_termios(g_ld, TCSANOW, &orig_term);
}

static void echoe_test(void) {
  KTEST_BEGIN("ld: disabling ECHOE");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);

  t.c_lflag &= ~ECHOE;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x04');
  KEXPECT_EQ(5, g_sink_idx);
  KEXPECT_STREQ("ab^?c", g_sink);

  // The ERASE character should have been applied to the buffer, however.
  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ac", buf);


  KTEST_BEGIN("ld: ECHOE but not ECHO");
  reset();
  ld_get_termios(g_ld, &t);
  t.c_lflag &= ~ECHO;
  t.c_lflag |= ECHOE;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, 'c');
  ld_provide(g_ld, '\x04');
  KEXPECT_EQ(0, g_sink_idx);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(2, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ac", buf);


  KTEST_BEGIN("ld: ECHOE but not ICANON");
  reset();
  ld_get_termios(g_ld, &t);
  t.c_lflag &= ~ICANON;
  t.c_lflag |= ECHOE;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provide(g_ld, 'a');
  ld_provide(g_ld, 'b');
  ld_provide(g_ld, '\x7f');
  ld_provide(g_ld, 'c');
  KEXPECT_EQ(5, g_sink_idx);
  KEXPECT_STREQ("ab^?c", g_sink);

  // The ERASE character should *not* have been applied to the buffer.
  kmemset(buf, 0, 10);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ab\x7f" "c", buf);
}

static void echonl_test(void) {
  KTEST_BEGIN("ld: disabling ECHONL");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);

  t.c_lflag &= ~ECHONL;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provides(g_ld, "ab\nc\x04");
  KEXPECT_EQ(4, g_sink_idx);
  KEXPECT_STREQ("ab\nc", g_sink);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ab\nc", buf);


  KTEST_BEGIN("ld: ECHONL but not ECHO");
  reset();
  ld_get_termios(g_ld, &t);
  t.c_lflag &= ~ECHO;
  t.c_lflag |= ECHONL;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provides(g_ld, "ab\nc\x04");
  KEXPECT_EQ(1, g_sink_idx);
  KEXPECT_EQ('\n', g_sink[0]);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ab\nc", buf);


  KTEST_BEGIN("ld: ECHONL but not ICANON");
  reset();
  ld_get_termios(g_ld, &t);
  t.c_lflag &= ~ICANON;
  t.c_lflag |= ECHONL;
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provides(g_ld, "ab\nc");
  KEXPECT_EQ(4, g_sink_idx);
  KEXPECT_STREQ("ab\nc", g_sink);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(4, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("ab\nc", buf);
}

static void change_control_char_test(void) {
  KTEST_BEGIN("ld: changing EOF character");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);

  t.c_cc[VEOF] = 'p';
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSANOW, &t));

  ld_provides(g_ld, "abc\x04" "d");
  KEXPECT_EQ(6, g_sink_idx);
  KEXPECT_STREQ("abc^Dd", g_sink);
  char buf[10];
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));

  ld_provide(g_ld, 'p');
  KEXPECT_EQ(6, g_sink_idx);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(5, ld_read(g_ld, buf, 10, 0));
  KEXPECT_STREQ("abc\x04" "d", buf);
}

static void set_attr_when_test(void) {
  KTEST_BEGIN("ld: ld_set_termios(TCSAFLUSH) applies changes now");
  reset();
  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  t.c_cc[VEOF] = 'p';
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSADRAIN, &t));

  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  KEXPECT_EQ('p', t.c_cc[VEOF]);
  char buf[10];
  KEXPECT_EQ(3, ld_read_async(g_ld, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("xyz", buf);


  KTEST_BEGIN("ld: ld_set_termios(TCSAFLUSH) flushes input");
  reset();
  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  t.c_cc[VEOF] = 'q';
  KEXPECT_EQ(0, ld_set_termios(g_ld, TCSAFLUSH, &t));

  kmemset(&t, 0xFF, sizeof(struct termios));
  ld_get_termios(g_ld, &t);
  KEXPECT_EQ('q', t.c_cc[VEOF]);
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));


  KTEST_BEGIN("ld: ld_set_termios() with invalid optional_actions arg");
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, -1, &t));
  KEXPECT_EQ(-EINVAL, ld_set_termios(g_ld, 50, &t));
}

static void drain_and_flush_test(void) {
  KTEST_BEGIN("ld: ld_drain() test (doesn't do anything)");
  reset();

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  KEXPECT_EQ(0, ld_drain(g_ld));
  KEXPECT_EQ(6, g_sink_idx);
  KEXPECT_STREQ("abcxyz", g_sink);

  char buf[10];
  kmemset(buf, '\0', 10);
  KEXPECT_EQ(3, ld_read_async(g_ld, buf, 10));
  KEXPECT_STREQ("xyz", buf);


  KTEST_BEGIN("ld: ld_flush(TCIFLUSH) test");
  reset();

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  KEXPECT_EQ(0, ld_flush(g_ld, TCIFLUSH));
  KEXPECT_EQ(6, g_sink_idx);
  KEXPECT_STREQ("abcxyz", g_sink);
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));


  KTEST_BEGIN("ld: ld_flush(TCOFLUSH) test");
  reset();

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  KEXPECT_EQ(0, ld_flush(g_ld, TCOFLUSH));
  KEXPECT_EQ(6, g_sink_idx);
  KEXPECT_STREQ("abcxyz", g_sink);
  kmemset(buf, '\0', 10);
  KEXPECT_EQ(3, ld_read_async(g_ld, buf, 10));
  KEXPECT_STREQ("xyz", buf);


  KTEST_BEGIN("ld: ld_flush(TCIOFLUSH) test");
  reset();

  KEXPECT_EQ(3, ld_write(g_ld, "abc", 3));
  ld_provides(g_ld, "xyz\x04");
  KEXPECT_EQ(0, ld_flush(g_ld, TCIOFLUSH));
  KEXPECT_EQ(6, g_sink_idx);
  KEXPECT_STREQ("abcxyz", g_sink);
  KEXPECT_EQ(-EAGAIN, ld_read_async(g_ld, buf, 10));


  KTEST_BEGIN("ld: ld_flush() invalid action test");
  KEXPECT_EQ(-EINVAL, ld_flush(g_ld, -1));
  KEXPECT_EQ(-EINVAL, ld_flush(g_ld, 8));
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
  termios_echo_test();
  termios_noncanon_read_test();
  termios_noncanon_test();
  control_chars_test();
  echoe_test();
  echonl_test();
  noflsh_test();
  change_control_char_test();
  set_attr_when_test();
  drain_and_flush_test();

  ld_destroy(g_ld);
  g_ld = NULL;
}
