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

#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/test_params.h"
#include "vfs/fifo.h"

static bool has_sigpipe(void) {
  const ksigset_t sigset = proc_pending_signals(proc_current());
  return ksigismember(&sigset, SIGPIPE);
}

// TODO(aoates): use signals to synchronize the threads.
static bool reader_open_finished = false;
static void* do_reader_open(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  intptr_t result = fifo_open(fifo, FIFO_READ, true, false);
  reader_open_finished = true;
  return (void*)result;
}

static bool writer_open_finished = false;
static void* do_writer_open(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  intptr_t result = fifo_open(fifo, FIFO_WRITE, true, false);
  writer_open_finished = true;
  return (void*)result;
}

static void do_reader_open_proc(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  int result = fifo_open(fifo, FIFO_READ, true, false);
  reader_open_finished = true;
  proc_exit(result);
}

static void do_writer_open_proc(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  int result = fifo_open(fifo, FIFO_WRITE, true, false);
  writer_open_finished = true;
  proc_exit(result);
}

static void open_test(void) {
  apos_fifo_t fifo;
  fifo_init(&fifo);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): non-blocking reader with no writers");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, false, false));
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, false, true));
  KEXPECT_EQ(2, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_READ);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): non-blocking writer with no readers");
  KEXPECT_EQ(-ENXIO, fifo_open(&fifo, FIFO_WRITE, false, false));
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, false, true));
  fifo_close(&fifo, FIFO_WRITE);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): blocking reader with a writer");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, false, true));
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, true, false));
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, true, false));
  KEXPECT_EQ(2, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);

  KTEST_BEGIN("fifo_open(): blocking writer with a reader");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, false, false));
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, true, false));
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, true, false));
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(2, fifo.num_writers);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_READ);


  KTEST_BEGIN("fifo_open(): blocking reader with no writer");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, false, false));

  kthread_t thread;
  reader_open_finished = false;
  KEXPECT_EQ(0, proc_thread_create(&thread, do_reader_open, &fifo));
  for (int i = 0; i < 10 && fifo.num_readers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, reader_open_finished);
  KEXPECT_EQ(2, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);
  KEXPECT_EQ(thread, fifo.read_queue.head);

  // Opening then closing immediately shouldn't make the original call return.
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, true, false));
  fifo_close(&fifo, FIFO_WRITE);
  for (int i = 0; i < 10 && !kthread_queue_empty(&fifo.write_queue); ++i)
    scheduler_yield();
  for (int i = 0; i < 10 && kthread_queue_empty(&fifo.write_queue); ++i)
    scheduler_yield();
  KEXPECT_EQ(false, reader_open_finished);

  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, true, false));
  KEXPECT_EQ(1, kthread_queue_empty(&fifo.read_queue));
  KEXPECT_EQ(0, (intptr_t)kthread_join(thread));
  KEXPECT_EQ(true, reader_open_finished);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);


  KTEST_BEGIN("fifo_open(): blocking writer with no reader");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, false, true));

  writer_open_finished = false;
  KEXPECT_EQ(0, proc_thread_create(&thread, do_writer_open, &fifo));
  for (int i = 0; i < 10 && fifo.num_writers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, writer_open_finished);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(2, fifo.num_writers);
  KEXPECT_EQ(thread, fifo.write_queue.head);

  // Opening then closing immediately shouldn't make the original call return.
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, true, false));
  fifo_close(&fifo, FIFO_READ);
  for (int i = 0; i < 10 && !kthread_queue_empty(&fifo.read_queue); ++i)
    scheduler_yield();
  for (int i = 0; i < 10 && kthread_queue_empty(&fifo.read_queue); ++i)
    scheduler_yield();
  KEXPECT_EQ(false, writer_open_finished);

  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, true, false));
  KEXPECT_EQ(1, kthread_queue_empty(&fifo.write_queue));
  KEXPECT_EQ(0, (intptr_t)kthread_join(thread));
  KEXPECT_EQ(true, writer_open_finished);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_WRITE);


  KTEST_BEGIN("fifo_open(): EINTR on signal (FIFO_READ)");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_READ, false, true));
  reader_open_finished = false;
  kpid_t child = proc_fork(&do_reader_open_proc, &fifo);
  KEXPECT_GE(child, 0);
  for (int i = 0; i < 10 && fifo.num_readers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, reader_open_finished);
  KEXPECT_EQ(2, fifo.num_readers);

  proc_force_signal(proc_get(child), SIGUSR1);
  for (int i = 0; i < 10 && fifo.num_readers == 2; ++i) scheduler_yield();
  KEXPECT_EQ(true, reader_open_finished);
  KEXPECT_EQ(1, fifo.num_readers);
  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(-EINTR, status);
  fifo_close(&fifo, FIFO_READ);


  KTEST_BEGIN("fifo_open(): EINTR on signal (FIFO_WRITE)");
  KEXPECT_EQ(0, fifo_open(&fifo, FIFO_WRITE, false, true));
  writer_open_finished = false;
  child = proc_fork(&do_writer_open_proc, &fifo);
  KEXPECT_GE(child, 0);
  for (int i = 0; i < 10 && fifo.num_writers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, writer_open_finished);
  KEXPECT_EQ(2, fifo.num_writers);

  proc_force_signal(proc_get(child), SIGUSR1);
  for (int i = 0; i < 10 && fifo.num_writers == 2; ++i) scheduler_yield();
  KEXPECT_EQ(true, writer_open_finished);
  KEXPECT_EQ(1, fifo.num_writers);
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(-EINTR, status);
  fifo_close(&fifo, FIFO_WRITE);


  // TODO(aoates): test that it's wake all, not wake one

  fifo_cleanup(&fifo);
}

typedef struct {
  apos_fifo_t* fifo;
  char* buf;
  size_t len;
  bool started;
  bool finished;
  int result;
} op_args_t;

static void* do_read(void* arg) {
  op_args_t* args = (op_args_t*)arg;
  args->finished = false;
  args->result = -1;
  args->started = true;
  args->result = fifo_read(args->fifo, args->buf, args->len, true);
  args->finished = true;
  return 0x0;
}

static void op_wait_start(op_args_t* args) {
  args->started = false;
  for (int i = 0; i < 10 && !args->started; ++i) scheduler_yield();
  KEXPECT_EQ(true, args->started);
}

static void op_wait_finish(const op_args_t* args) {
  for (int i = 0; i < 10 && !args->finished; ++i) scheduler_yield();
  KEXPECT_EQ(true, args->finished);
}

static void do_read_proc(void* arg) {
  do_read(arg);
}

static void read_test(void) {
  apos_fifo_t f;
  char buf[100];
  kthread_t thread;

  KTEST_BEGIN("fifo_read(): basic read [blocking]");
  fifo_init(&f);
  KEXPECT_EQ(0, fifo_open(&f, FIFO_WRITE, false, true));

  KEXPECT_EQ(0, fifo_open(&f, FIFO_READ, false, false));
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "abcde", 5));
  KEXPECT_EQ(5, fifo_read(&f, buf, 100, true));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  KTEST_BEGIN("fifo_read(): basic read [non-blocking]");
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "ABCDE", 5));
  KEXPECT_EQ(5, fifo_read(&f, buf, 100, false));
  buf[5] = '\0';
  KEXPECT_STREQ("ABCDE", buf);


  KTEST_BEGIN("fifo_read(): buffer too small [blocking]");
  kmemset(buf, '\0', 100);
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "abcde", 5));
  KEXPECT_EQ(3, fifo_read(&f, buf, 3, true));
  KEXPECT_STREQ("abc", buf);


  KTEST_BEGIN("fifo_read(): buffer too small [non-blocking]");
  kmemset(buf, '\0', 100);
  f.cbuf.len = 0;  // TODO(aoates): write circbuf_clear()
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "abcde", 5));
  KEXPECT_EQ(3, fifo_read(&f, buf, 3, false));
  KEXPECT_STREQ("abc", buf);


  KTEST_BEGIN("fifo_read(): no data -> block until available");
  f.cbuf.len = 0;
  op_args_t args;
  args.fifo = &f;
  args.buf = buf;
  args.len = 100;

  kmemset(buf, '\0', 100);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_read, &args));
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);

  KEXPECT_EQ(3, fifo_write(&f, "123", 3, true));
  op_wait_finish(&args);
  KEXPECT_EQ(3, args.result);
  buf[3] = '\0';
  KEXPECT_STREQ("123", buf);
  kthread_join(thread);


  KTEST_BEGIN("fifo_read(): no data [non-blocking] -> return EAGAIN");
  KEXPECT_EQ(-EAGAIN, fifo_read(&f, buf, 100, false));


  KTEST_BEGIN("fifo_read(): no data and no writers -> return 0");
  fifo_close(&f, FIFO_WRITE);
  KEXPECT_EQ(0, fifo_read(&f, buf, 100, true));


  KTEST_BEGIN("fifo_read(): no data and no writers [non-blocking] -> return 0");
  KEXPECT_EQ(0, fifo_read(&f, buf, 100, false));

  KTEST_BEGIN("fifo_read(): blocking until writer closes -> return 0");
  KEXPECT_EQ(0, fifo_open(&f, FIFO_WRITE, false, true));
  f.cbuf.len = 0;
  args.fifo = &f;
  args.buf = buf;
  args.len = 100;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_read, &args));
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);

  fifo_close(&f, FIFO_WRITE);
  op_wait_finish(&args);
  KEXPECT_EQ(0, args.result);
  kthread_join(thread);


  KTEST_BEGIN("fifo_read(): no writers but has data");
  kmemset(buf, '\0', 100);
  f.cbuf.len = 0;  // TODO(aoates): write circbuf_clear()
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "abcde", 5));
  KEXPECT_EQ(0, f.num_writers);
  KEXPECT_EQ(3, fifo_read(&f, buf, 3, true));
  KEXPECT_STREQ("abc", buf);

  KEXPECT_EQ(2, fifo_read(&f, buf, 5, true));
  KEXPECT_STREQ("dec", buf);

  KEXPECT_EQ(0, fifo_read(&f, buf, 5, true));

  KTEST_BEGIN("fifo_read(): given len is 0 (should never block)");
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, true));
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, false));
  KEXPECT_EQ(5, circbuf_write(&f.cbuf, "abcde", 5));
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, true));
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, false));
  KEXPECT_EQ(0, fifo_open(&f, FIFO_WRITE, false, false));
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, true));
  KEXPECT_EQ(0, fifo_read(&f, buf, 0, false));
  fifo_close(&f, FIFO_WRITE);


  KTEST_BEGIN("fifo_read(): interrupted by signal");
  f.cbuf.pos = f.cbuf.len = 0;
  args.len = 10;
  KEXPECT_EQ(0, fifo_open(&f, FIFO_WRITE, false, true));
  kpid_t child = proc_fork(do_read_proc, &args);
  KEXPECT_GE(child, 0);
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);

  proc_force_signal(proc_get(child), SIGUSR1);
  op_wait_finish(&args);
  KEXPECT_EQ(-EINTR, args.result);
  KEXPECT_EQ(child, proc_wait(NULL));

  fifo_close(&f, FIFO_WRITE);
  fifo_close(&f, FIFO_READ);
  fifo_cleanup(&f);
}

static void* do_write(void* arg) {
  op_args_t* args = (op_args_t*)arg;
  args->finished = false;
  args->result = -1;
  args->started = true;
  args->result = fifo_write(args->fifo, args->buf, args->len, true);
  args->finished = true;
  return 0x0;
}

static void do_write_proc(void* arg) {
  do_write(arg);
}

static int check_buffer3(const void* buf, char c1, int len1, char c2, int len2,
                         char c3, int len3) {
  for (int i = 0; i < len1; ++i) {
    if (((const char*)buf)[i] != c1) return 1;
  }
  for (int i = 0; i < len2; ++i) {
    if (((const char*)buf)[i + len1] != c2) return 1;
  }
  for (int i = 0; i < len3; ++i) {
    if (((const char*)buf)[i + len1 + len2] != c3) return 1;
  }
  return 0;
}

static int check_buffer(const void* buf, char c1, int len1, char c2, int len2) {
  return check_buffer3(buf, c1, len1, c2, len2, '!', 0);
}

static void circbuf_realign(circbuf_t* cbuf) {
  void* tmp = kmalloc(cbuf->buflen);
  int orig_len = cbuf->len;
  KEXPECT_EQ(orig_len, circbuf_read(cbuf, tmp, orig_len));
  KASSERT(cbuf->len == 0);
  cbuf->pos = 0;
  KEXPECT_EQ(orig_len, circbuf_write(cbuf, tmp, orig_len));
  kfree(tmp);
}

const int kBigBufSize = 2 * APOS_FIFO_BUF_SIZE;

static void write_testA(apos_fifo_t* f, void* big_buf, void* big_buf2) {
  char buf[100];
  kthread_t thread;

  KTEST_BEGIN("fifo_write(): basic write [blocking]");
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));

  KEXPECT_EQ(0, fifo_open(f, FIFO_WRITE, false, true));
  KEXPECT_EQ(5, fifo_write(f, "abcde", 5, true));
  KEXPECT_EQ(5, circbuf_read(&f->cbuf, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  KTEST_BEGIN("fifo_write(): basic write [non-blocking]");
  KEXPECT_EQ(5, fifo_write(f, "ABCDE", 5, false));
  KEXPECT_EQ(5, circbuf_read(&f->cbuf, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("ABCDE", buf);

  KTEST_BEGIN("fifo_write(): can write partial data [blocking]");
  kmemset(big_buf, 'x', kBigBufSize);
  const int write_size = APOS_FIFO_BUF_SIZE - APOS_FIFO_MAX_ATOMIC_WRITE - 200;
  KEXPECT_EQ(write_size, circbuf_write(&f->cbuf, big_buf, write_size));
  kmemset(big_buf, 'X', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_MAX_ATOMIC_WRITE + 200,
             fifo_write(f, big_buf, APOS_FIFO_MAX_ATOMIC_WRITE + 200, true));
  kmemset(big_buf2, 'y', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, circbuf_read(&f->cbuf, big_buf2, kBigBufSize));
  kmemset(big_buf, 'x', write_size);
  kmemset(big_buf + write_size, 'X', APOS_FIFO_MAX_ATOMIC_WRITE + 200);
  KEXPECT_EQ(0, kstrncmp(big_buf, big_buf2, APOS_FIFO_BUF_SIZE));


  KTEST_BEGIN("fifo_write(): can write partial data [non-blocking]");
  kmemset(big_buf2, 'x', kBigBufSize);
  KEXPECT_EQ(write_size, circbuf_write(&f->cbuf, big_buf, write_size));
  kmemset(big_buf2, 'X', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_MAX_ATOMIC_WRITE + 200,
             fifo_write(f, big_buf2, APOS_FIFO_MAX_ATOMIC_WRITE + 200, false));
  kmemset(big_buf2, 'y', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, circbuf_read(&f->cbuf, big_buf2, kBigBufSize));
  KEXPECT_EQ(0, kstrncmp(big_buf, big_buf2, APOS_FIFO_BUF_SIZE));


  KTEST_BEGIN("fifo_write(): buffer too small [blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(f->buf, '?', APOS_FIFO_BUF_SIZE);
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(200, circbuf_write(&f->cbuf, big_buf, 200));
  kmemset(big_buf, 'X', kBigBufSize);

  op_args_t args;
  args.fifo = f;
  args.buf = big_buf;
  args.len = APOS_FIFO_BUF_SIZE - 100;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);

  // Open up some space, but not enough.
  KEXPECT_EQ(50, fifo_read(f, big_buf2, 50, true));
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  KEXPECT_EQ(false, args.finished);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0, check_buffer(big_buf2, 'x', 50, 'X', 0));
  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(0,
             check_buffer(f->cbuf.buf, 'x', 150, 'X', APOS_FIFO_BUF_SIZE - 150));

  // Open up the rest.
  KEXPECT_EQ(160, fifo_read(f, big_buf2, 160, true));
  op_wait_finish(&args);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100, args.result);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 110, f->cbuf.len);
  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(0, check_buffer(big_buf2, 'x', 150, 'X', 10));
  KEXPECT_EQ(0, check_buffer(f->cbuf.buf, 'x', 0, 'X', APOS_FIFO_BUF_SIZE - 10));
  kthread_join(thread);
}

static void write_testB(apos_fifo_t* f, void* big_buf, void* big_buf2) {
  kthread_t thread;
  op_args_t args;
  args.fifo = f;
  args.buf = big_buf;
  args.len = APOS_FIFO_BUF_SIZE - 100;

  KTEST_BEGIN("fifo_write(): buffer too small [non-blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(200, circbuf_write(&f->cbuf, big_buf, 200));
  kmemset(big_buf, 'X', kBigBufSize);

  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 200,
             fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE - 100, false));

  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0,
             check_buffer(f->cbuf.buf, 'x', 200, 'X', APOS_FIFO_BUF_SIZE - 200));


  KTEST_BEGIN("fifo_write(): buffer full [blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             circbuf_write(&f->cbuf, big_buf, APOS_FIFO_BUF_SIZE));
  kmemset(big_buf, 'X', kBigBufSize);

  args.len = APOS_FIFO_BUF_SIZE - 100;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);
  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0, check_buffer(f->buf, 'x', APOS_FIFO_BUF_SIZE, 'X', 0));

  // Open up some space, but not enough.
  KEXPECT_EQ(50, fifo_read(f, big_buf2, 50, true));
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0,
             check_buffer(f->cbuf.buf, 'x', APOS_FIFO_BUF_SIZE - 50, 'X', 50));

  // Open up the rest.
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             fifo_read(f, big_buf2, APOS_FIFO_BUF_SIZE, true));
  op_wait_finish(&args);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE- 100, args.result);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 150, f->cbuf.len);
  KEXPECT_EQ(0,
             check_buffer(f->cbuf.buf, 'x', 0, 'X', APOS_FIFO_BUF_SIZE - 150));
  kthread_join(thread);


  KTEST_BEGIN("fifo_write(): buffer full [non-blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             circbuf_write(&f->cbuf, big_buf, APOS_FIFO_BUF_SIZE));
  kmemset(big_buf, 'X', kBigBufSize);

  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, 100, false));
  KEXPECT_EQ(-EAGAIN,
             fifo_write(f, big_buf, APOS_FIFO_MAX_ATOMIC_WRITE, false));
  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE - 100, false));
  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE, false));

  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0, check_buffer(f->cbuf.buf, 'x', APOS_FIFO_BUF_SIZE, 'X', 0));
}

static void write_testC(apos_fifo_t* f, void* big_buf, void* big_buf2) {
  kthread_t thread;
  op_args_t args;
  args.fifo = f;
  args.buf = big_buf;

  KTEST_BEGIN("fifo_write(): atomic write into buffer too small [blocking]");
  // Atomic write sizes to test.  Tuples of atomic write size, how much space to
  // leave in the buffer before writing, and how much to read to make sure a
  // partial read doesn't cause a non-atomic write.
  const int kAtomicWriteSizes[][3] = {
      {1, 0, 0},
      {200, 100, 50},
      {APOS_FIFO_MAX_ATOMIC_WRITE - 1, 200, 100},
      {APOS_FIFO_MAX_ATOMIC_WRITE, 200, 100},
      {-1, -1, -1}};
  for (int i = 0; kAtomicWriteSizes[i][0] > 0; ++i) {
    KLOG("Testing atomic write of %d bytes\n", kAtomicWriteSizes[i][0]);
    KASSERT(kAtomicWriteSizes[i][1] + kAtomicWriteSizes[i][2] <
            kAtomicWriteSizes[i][0]);
    f->cbuf.pos = f->cbuf.len = 0;
    kmemset(big_buf, 'x', kBigBufSize);
    const int orig_write_size = APOS_FIFO_BUF_SIZE - kAtomicWriteSizes[i][1];
    KEXPECT_EQ(orig_write_size,
               circbuf_write(&f->cbuf, big_buf, orig_write_size));
    kmemset(big_buf, 'X', kBigBufSize);
    args.len = kAtomicWriteSizes[i][0];

    KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
    op_wait_start(&args);
    KEXPECT_EQ(false, args.finished);
    KEXPECT_EQ(orig_write_size, f->cbuf.len);

    const int read_size1 = kAtomicWriteSizes[i][2];
    if (read_size1 > 0) {
      // Open up some space, but not enough.
      KEXPECT_EQ(read_size1, fifo_read(f, big_buf2, read_size1, true));
      for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
      KEXPECT_EQ(false, args.finished);
      KEXPECT_EQ(orig_write_size - read_size1, f->cbuf.len);
      KEXPECT_EQ(0, check_buffer(big_buf2, 'x', read_size1, 'X', 0));
      circbuf_realign(&f->cbuf);
      KEXPECT_EQ(0, check_buffer(f->cbuf.buf, 'x', orig_write_size - read_size1,
                                 'X', 0));
    }

    const int num_ys = min(read_size1, 7);
    if (num_ys > 0) {
      // Make a second write.
      KEXPECT_EQ(7, fifo_write(f, "yyyyyyy", 7, false));
    }

    // Open up the rest.
    const int read_size2 = kAtomicWriteSizes[i][0] - read_size1 + 10;
    KEXPECT_EQ(read_size2, fifo_read(f, big_buf2, read_size2, true));
    op_wait_finish(&args);
    KEXPECT_EQ(kAtomicWriteSizes[i][0], args.result);
    KEXPECT_EQ(orig_write_size - read_size1 - read_size2 + num_ys +
                   kAtomicWriteSizes[i][0],
               f->cbuf.len);
    circbuf_realign(&f->cbuf);
    KEXPECT_EQ(0, check_buffer(big_buf2, 'x', read_size2, 'X', 0));
    KEXPECT_EQ(0, check_buffer3(f->cbuf.buf, 'x',
                                orig_write_size - read_size1 - read_size2, 'y',
                                num_ys, 'X', kAtomicWriteSizes[i][0]));
    kthread_join(thread);
  }
}

static void write_testD(apos_fifo_t* f, void* big_buf, void* big_buf2) {
  kthread_t thread;
  op_args_t args;
  args.fifo = f;
  args.buf = big_buf;

  KTEST_BEGIN(
      "fifo_write(): atomic write into buffer too small [non-blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100,
             circbuf_write(&f->cbuf, big_buf, APOS_FIFO_BUF_SIZE - 100));
  kmemset(big_buf, 'X', kBigBufSize);

  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, 101, false));
  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, 200, false));
  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, 300, false));
  KEXPECT_EQ(-EAGAIN, fifo_write(f, big_buf, 500, false));
  KEXPECT_EQ(100, fifo_write(f, big_buf, 600, false));



  KTEST_BEGIN("fifo_write(): write bigger than buffer [blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'X', kBigBufSize);
  args.len = APOS_FIFO_BUF_SIZE * 1.5;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);
  circbuf_realign(&f->cbuf);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0, check_buffer(f->buf, 'x', 0, 'X', APOS_FIFO_BUF_SIZE));

  // Open up some space, but not enough.
  KEXPECT_EQ(50, fifo_read(f, big_buf2, 50, true));
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);

  KEXPECT_EQ(50, fifo_read(f, big_buf2, 50, true));
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);

  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             fifo_read(f, big_buf2, APOS_FIFO_BUF_SIZE, true));
  op_wait_finish(&args);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE / 2 - 100, f->cbuf.len);

  kthread_join(thread);



  KTEST_BEGIN("fifo_write(): write bigger than buffer [non-blocking]");
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'X', kBigBufSize);

  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE * 1.5, false));



  KTEST_BEGIN("fifo_write(): write when there are no readers [non-blocking]");
  fifo_close(f, FIFO_READ);
  KEXPECT_EQ(false, has_sigpipe());

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, 0, false));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, 100, false));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE,
             fifo_write(f, big_buf, APOS_FIFO_MAX_ATOMIC_WRITE + 10, false));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE + 10, false));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);



  KTEST_BEGIN("fifo_write(): write when there are no readers [blocking]");
  KEXPECT_EQ(false, has_sigpipe());

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, 0, true));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, 100, true));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE,
             fifo_write(f, big_buf, APOS_FIFO_MAX_ATOMIC_WRITE + 10, true));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(-EPIPE, fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE + 10, true));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);



  KTEST_BEGIN("fifo_write(): blocking write when last reader closes");
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'X', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE,
             fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE, false));

  args.len = 100;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
  op_wait_start(&args);

  // Close second-to-last reader.
  fifo_close(f, FIFO_READ);
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  KEXPECT_EQ(false, args.finished);

  // Close last reader.
  KEXPECT_EQ(false, has_sigpipe());
  fifo_close(f, FIFO_READ);
  op_wait_finish(&args);
  KEXPECT_EQ(-EPIPE, args.result);
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  kthread_join(thread);



  KTEST_BEGIN(
      "fifo_write(): blocking write when last reader closes (data already "
      "written)");
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));
  f->cbuf.pos = f->cbuf.len = 0;
  kmemset(big_buf, 'x', kBigBufSize);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100,
             fifo_write(f, big_buf, APOS_FIFO_BUF_SIZE - 100, false));
  kmemset(big_buf, 'X', kBigBufSize);

  args.len = APOS_FIFO_BUF_SIZE;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_write, &args));
  op_wait_start(&args);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);

  // Close second-to-last reader.
  fifo_close(f, FIFO_READ);
  for (int i = 0; i < 10 && !f->write_queue.head; ++i) scheduler_yield();
  KEXPECT_EQ(false, args.finished);

  // Close last reader.
  KEXPECT_EQ(false, has_sigpipe());
  fifo_close(f, FIFO_READ);
  op_wait_finish(&args);
  KEXPECT_EQ(-EPIPE, args.result);
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);
  KEXPECT_EQ(0,
             check_buffer(f->cbuf.buf, 'x', APOS_FIFO_BUF_SIZE - 100, 'X', 100));

  kthread_join(thread);


  KTEST_BEGIN("fifo_write(): interrupted by signal (no data written)");
  f->cbuf.pos = f->cbuf.len = 0;
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100,
             circbuf_write(&f->cbuf, big_buf, APOS_FIFO_BUF_SIZE - 100));
  args.len = 200;
  KEXPECT_EQ(0, fifo_open(f, FIFO_READ, false, false));
  kpid_t child = proc_fork(do_write_proc, &args);
  KEXPECT_GE(child, 0);
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);

  proc_force_signal(proc_get(child), SIGUSR1);
  op_wait_finish(&args);
  KEXPECT_EQ(-EINTR, args.result);
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100, f->cbuf.len);


  KTEST_BEGIN("fifo_write(): interrupted by signal (data already written)");
  f->cbuf.pos = f->cbuf.len = 0;
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE - 100,
             circbuf_write(&f->cbuf, big_buf, APOS_FIFO_BUF_SIZE - 100));
  args.len = APOS_FIFO_MAX_ATOMIC_WRITE + 100;
  child = proc_fork(do_write_proc, &args);
  KEXPECT_GE(child, 0);
  op_wait_start(&args);
  KEXPECT_EQ(false, args.finished);

  proc_force_signal(proc_get(child), SIGUSR1);
  op_wait_finish(&args);
  KEXPECT_EQ(100, args.result);
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE, f->cbuf.len);


  fifo_close(f, FIFO_READ);
  fifo_close(f, FIFO_WRITE);
}

static void write_test(void) {
  apos_fifo_t f;
  void* big_buf = kmalloc(kBigBufSize);
  void* big_buf2 = kmalloc(kBigBufSize);
  fifo_init(&f);

  write_testA(&f, big_buf, big_buf2);
  write_testB(&f, big_buf, big_buf2);
  write_testC(&f, big_buf, big_buf2);
  write_testD(&f, big_buf, big_buf2);

  fifo_cleanup(&f);
  kfree(big_buf);
  kfree(big_buf2);
}

typedef struct {
  apos_fifo_t fifo;
} fifo_mt_args_t;

static void* fifo_mt_thread_read(void* arg) {
  sched_enable_preemption_for_test();
  fifo_mt_args_t* args = (fifo_mt_args_t*)arg;
  KEXPECT_EQ(0, fifo_open(&args->fifo, FIFO_READ, true, false));
  char c;
  int i = 0;
  uintptr_t read = 0;
  while (1) {
    i++;
    bool block = (i % 2 == 0);
    c = '?';
    int result = fifo_read(&args->fifo, &c, 1, block);
    if (result == -EINTR) break;
    if (block) {
      KEXPECT_EQ(1, result);
    } else {
      KEXPECT_TRUE(result == 1 || result == -EAGAIN);
    }
    if (result > 0) {
      KEXPECT_EQ('x', c);
      read += result;
    }
  }
  fifo_close(&args->fifo, FIFO_READ);
  return (void*)read;
}

static void* fifo_mt_thread_write(void* arg) {
  sched_enable_preemption_for_test();
  fifo_mt_args_t* args = (fifo_mt_args_t*)arg;
  KEXPECT_EQ(0, fifo_open(&args->fifo, FIFO_WRITE, true, false));
  uintptr_t i = 0;
  for (i = 0; i < 100 * CONCURRENCY_TEST_ITERS_MULT; /* nop */) {
    bool block = (i % 2 == 0);
    int result = fifo_write(&args->fifo, "x", 1, block);
    if (block) {
      KEXPECT_EQ(1, result);
    } else {
      KEXPECT_TRUE(result == 1 || result == -EAGAIN);
    }
    if (result > 0) {
      i++;
    }
  }
  fifo_close(&args->fifo, FIFO_WRITE);
  return (void*)i;
}

// A basic multi-threaded stress test.
static void multi_thread_test(void) {
  KTEST_BEGIN("FIFO: multi-threaded test");
  const int kNumThreads = 5 * CONCURRENCY_TEST_THREADS_MULT;
  kthread_t readers[kNumThreads], writers[kNumThreads];

  fifo_mt_args_t args;
  fifo_init(&args.fifo);

  // Open one writer so that readers will start immediately.
  KEXPECT_EQ(0, fifo_open(&args.fifo, FIFO_WRITE, false, true));

  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&readers[i], fifo_mt_thread_read, &args));
    KEXPECT_EQ(0, proc_thread_create(&writers[i], fifo_mt_thread_write, &args));
  }
  uintptr_t read = 0, written = 0;
  for (int i = 0; i < kNumThreads; ++i) {
    written += (uintptr_t)kthread_join(writers[i]);
  }
  for (int i = 0; i < kNumThreads; ++i) {
    proc_force_signal_on_thread(readers[i]->process, readers[i], SIGUSR1);
    read += (uintptr_t)kthread_join(readers[i]);
  }
  fifo_close(&args.fifo, FIFO_WRITE);
  fifo_cleanup(&args.fifo);

  KEXPECT_GE(written, 200);
  KEXPECT_EQ(read, written);
}

void fifo_test(void) {
  KTEST_SUITE_BEGIN("FIFO");
  open_test();
  read_test();
  write_test();
  multi_thread_test();
}
