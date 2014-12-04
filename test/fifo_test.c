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

#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "test/ktest.h"
#include "vfs/fifo.h"

// Tests to write:
//  - open: non-blocking reader, non-blocking writer
//  - open: blocking reader, blocking writer (doesn't block)
//  - open: blocking reader, blocking writer (does block)

// TODO(aoates): use signals to synchronize the threads.
static bool reader_open_finished = false;
static void* do_reader_open(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  fifo_open(fifo, FIFO_READ, true);
  reader_open_finished = true;
  return 0x0;
}

static bool writer_open_finished = false;
static void* do_writer_open(void* arg) {
  apos_fifo_t* fifo = (apos_fifo_t*)arg;
  fifo_open(fifo, FIFO_WRITE, true);
  writer_open_finished = true;
  return 0x0;
}

static void open_test(void) {
  apos_fifo_t fifo;
  fifo_init(&fifo);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): non-blocking reader with no writers");
  fifo_open(&fifo, FIFO_READ, false);
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);
  fifo_close(&fifo, FIFO_READ);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): non-blocking writer with no readers");
  fifo_open(&fifo, FIFO_WRITE, false);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  fifo_close(&fifo, FIFO_WRITE);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);

  KTEST_BEGIN("fifo_open(): blocking reader with a writer");
  fifo_open(&fifo, FIFO_WRITE, false);
  fifo_open(&fifo, FIFO_READ, true);
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  fifo_open(&fifo, FIFO_READ, true);
  KEXPECT_EQ(2, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);

  KTEST_BEGIN("fifo_open(): blocking writer with a reader");
  fifo_open(&fifo, FIFO_READ, false);
  fifo_open(&fifo, FIFO_WRITE, true);
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(1, fifo.num_writers);
  fifo_open(&fifo, FIFO_WRITE, true);
  KEXPECT_EQ(1, fifo.num_readers);
  KEXPECT_EQ(2, fifo.num_writers);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_READ);


  KTEST_BEGIN("fifo_open(): blocking reader with no writer");
  fifo_open(&fifo, FIFO_READ, false);

  kthread_t thread;
  reader_open_finished = false;
  KEXPECT_EQ(0, kthread_create(&thread, do_reader_open, &fifo));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 10 && fifo.num_readers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, reader_open_finished);
  KEXPECT_EQ(2, fifo.num_readers);
  KEXPECT_EQ(0, fifo.num_writers);
  KEXPECT_EQ(thread, fifo.read_queue.head);

  // Opening then closing immediately shouldn't make the original call return.
  fifo_open(&fifo, FIFO_WRITE, true);
  fifo_close(&fifo, FIFO_WRITE);
  for (int i = 0; i < 10 && !kthread_queue_empty(&fifo.write_queue); ++i)
    scheduler_yield();
  for (int i = 0; i < 10 && kthread_queue_empty(&fifo.write_queue); ++i)
    scheduler_yield();
  KEXPECT_EQ(false, reader_open_finished);

  fifo_open(&fifo, FIFO_WRITE, true);
  KEXPECT_EQ(1, kthread_queue_empty(&fifo.read_queue));
  kthread_join(thread);
  KEXPECT_EQ(true, reader_open_finished);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);


  KTEST_BEGIN("fifo_open(): blocking writer with no reader");
  fifo_open(&fifo, FIFO_WRITE, false);

  writer_open_finished = false;
  KEXPECT_EQ(0, kthread_create(&thread, do_writer_open, &fifo));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 10 && fifo.num_writers == 1; ++i) scheduler_yield();
  KEXPECT_EQ(false, writer_open_finished);
  KEXPECT_EQ(0, fifo.num_readers);
  KEXPECT_EQ(2, fifo.num_writers);
  KEXPECT_EQ(thread, fifo.write_queue.head);

  // Opening then closing immediately shouldn't make the original call return.
  fifo_open(&fifo, FIFO_READ, true);
  fifo_close(&fifo, FIFO_READ);
  for (int i = 0; i < 10 && !kthread_queue_empty(&fifo.read_queue); ++i)
    scheduler_yield();
  for (int i = 0; i < 10 && kthread_queue_empty(&fifo.read_queue); ++i)
    scheduler_yield();
  KEXPECT_EQ(false, writer_open_finished);

  fifo_open(&fifo, FIFO_READ, true);
  KEXPECT_EQ(1, kthread_queue_empty(&fifo.write_queue));
  kthread_join(thread);
  KEXPECT_EQ(true, writer_open_finished);
  fifo_close(&fifo, FIFO_READ);
  fifo_close(&fifo, FIFO_WRITE);
  fifo_close(&fifo, FIFO_WRITE);

  // TODO(aoates): test that it's wake all, not wake one

  fifo_cleanup(&fifo);
}

void fifo_test(void) {
  KTEST_SUITE_BEGIN("FIFO");
  open_test();
}
