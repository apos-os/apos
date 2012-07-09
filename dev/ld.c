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
#include "kmalloc.h"
#include "dev/char.h"
#include "dev/interrupts.h"
#include "dev/ld.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

struct ld {
  // Circular buffer of characters ready to be read.  Indexed by {start, cooked,
  // raw}_idx, which refer to the first character, the end of the cooked region,
  // and the end of the raw region respectively.
  //  start_idx <= cooked_idx <= raw_idx
  // (subject to circular index rollover).
  char* read_buf;
  int buf_len;
  uint32_t start_idx;
  uint32_t cooked_idx;
  uint32_t raw_idx;

  // The character sink for echoing and writing.
  char_sink_t sink;
  void* sink_arg;

  // Threads that are waiting for cooked data to be available in the buffer.
  kthread_queue_t wait_queue;
};
typedef struct ld ld_t;

ld_t* ld_create(int buf_size) {
  ld_t* l = (ld_t*)kmalloc(sizeof(ld_t));
  l->read_buf = (char*)kmalloc(buf_size);
  l->buf_len = buf_size;
  l->start_idx = l->cooked_idx = l->raw_idx = 0;
  l->sink = 0x0;
  l->sink_arg = 0x0;
  kthread_queue_init(&l->wait_queue);
  return l;
}

void ld_destroy(ld_t* l) {
  if (l->read_buf) {
    kfree(l->read_buf);
  }
  kfree(l);
}

static inline uint32_t circ_inc(ld_t* l, uint32_t x) {
  return (x + 1) % l->buf_len;
}

static inline uint32_t circ_dec(ld_t* l, uint32_t x) {
  if (x == 0) return l->buf_len - 1;
  else return x - 1;
}

static void cook_buffer(ld_t* l) {
  l->cooked_idx = l->raw_idx;

  // Wake up all the waiting threads.
  // TODO(aoates): this should probably be a higher-level primitive (or at least
  // a convenience function).
  kthread_t t = kthread_queue_pop(&l->wait_queue);
  while (t) {
    scheduler_make_runnable(t);
    t = kthread_queue_pop(&l->wait_queue);
  }
}

void log_state(ld_t* l) {
  klogf("ld state:\n");
  char buf[l->buf_len+2];
  for (int i = 0; i < l->buf_len; i++) {
    buf[i] = l->read_buf[i];
    if (buf[i] < 32) {
      buf[i] = '?';
    }
  }
  buf[l->buf_len] = '\n';
  buf[l->buf_len+1] = '\0';
  klog(buf);

  kmemset(buf, ' ', l->buf_len);
  buf[l->start_idx] = 's';
  klog(buf);

  kmemset(buf, ' ', l->buf_len);
  buf[l->cooked_idx] = 'c';
  klog(buf);

  kmemset(buf, ' ', l->buf_len);
  buf[l->raw_idx] = 'r';
  klog(buf);
}

void ld_provide(ld_t* l, char c) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);

  // Check for overflow.
  if (c != '\b' && circ_inc(l, l->raw_idx) == l->start_idx) {
    char buf[2];
    buf[0] = c;
    buf[1] = '\0';
    klogf("WARNING: ld buffer full; dropping char '%s'\n", buf);
    return;
  }

  int echo = 1;
  switch (c) {
    case '\b':
      if (l->cooked_idx == l->raw_idx) {
        // Ignore backspace at start of line.
        return;
      }
      l->raw_idx = circ_dec(l, l->raw_idx);
      l->read_buf[l->raw_idx] = '#';  // DEBUG
      break;

    case ASCII_EOT:
      echo = 0;
      break;

    case '\r':
    case '\f':
      die("ld cannot handle '\\r' or '\\f' characters (only '\\n')");
      break;

    // TODO(aoates): handle other special chars.
    default:
      if (c < 32 && c != '\n') {
        klogf("WARNING: ignoring unknown control char 0x%x in ld\n");
        return;
      }

      l->read_buf[l->raw_idx] = c;
      l->raw_idx = circ_inc(l, l->raw_idx);
  }

  // Echo it to the screen.
  if (echo) {
    l->sink(l->sink_arg, c);
  }

  // Cook the buffer, optionally.
  // TODO(aoates): handle ctrl-c, ctrl-d, etc.
  if (c == '\n' || c == ASCII_EOT) {
    cook_buffer(l);
  }
}

void ld_set_sink(ld_t* l, char_sink_t sink, void* arg) {
  l->sink = sink;
  l->sink_arg = arg;
}

static int ld_read_internal(ld_t* l, char* buf, int n) {
  int copied = 0;
  int buf_idx = 0;
  while (l->start_idx != l->cooked_idx && copied < n) {
    buf[buf_idx] = l->read_buf[l->start_idx];
    buf_idx++;
    copied++;
    l->start_idx = circ_inc(l, l->start_idx);
  }
  return copied;
}

int ld_read(ld_t* l, char* buf, int n) {
  PUSH_AND_DISABLE_INTERRUPTS();
  while (l->start_idx == l->cooked_idx) {
    // Block until data is available.
    scheduler_wait_on(&l->wait_queue);
  }

  // TODO(aoates): handle end-of-stream.
  int copied = ld_read_internal(l, buf, n);
  POP_INTERRUPTS();
  return copied;
}

int ld_read_async(ld_t* l, char* buf, int n) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int copied = ld_read_internal(l, buf, n);
  POP_INTERRUPTS();
  return copied;
}

int ld_write(ld_t* l, char* buf, int n) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);

  for (int i = 0; i < n; ++i) {
    l->sink(l->sink_arg, buf[i]);
  }

  return n;
}
