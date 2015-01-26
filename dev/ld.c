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
#include "memory/kmalloc.h"
#include "dev/char_dev.h"
#include "dev/interrupts.h"
#include "dev/ld.h"
#include "dev/tty.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "user/include/apos/termios.h"

struct ld {
  // Circular buffer of characters ready to be read.  Indexed by {start, cooked,
  // raw}_idx, which refer to the first character, the end of the cooked region,
  // and the end of the raw region respectively.
  //  start_idx <= cooked_idx <= raw_idx
  // (subject to circular index rollover).
  char* read_buf;
  int buf_len;
  size_t start_idx;
  size_t cooked_idx;
  size_t raw_idx;

  // The character sink for echoing and writing.
  char_sink_t sink;
  void* sink_arg;

  // Threads that are waiting for cooked data to be available in the buffer.
  kthread_queue_t wait_queue;

  apos_dev_t tty;
  struct termios termios;
};

static void set_default_termios(struct termios* t) {
  t->c_iflag = 0;
  t->c_oflag = 0;
  t->c_cflag = CS8;
  t->c_lflag = ECHO | ECHOE | ECHOK | ICANON | ISIG;

  // TODO(aoates): implement the rest of these.
  t->c_cc[VEOF] = ASCII_EOT;
  t->c_cc[VEOL] = _POSIX_VDISABLE;
  t->c_cc[VERASE] = ASCII_DEL;
  t->c_cc[VINTR] = ASCII_ETX;
  t->c_cc[VKILL] = _POSIX_VDISABLE;
  t->c_cc[VMIN] = 1;
  t->c_cc[VQUIT] = ASCII_FS;
  t->c_cc[VSTART] = _POSIX_VDISABLE;
  t->c_cc[VSTOP] = _POSIX_VDISABLE;
  t->c_cc[VSUSP] = ASCII_SUB;
  t->c_cc[VTIME] = 0;
}

ld_t* ld_create(int buf_size) {
  ld_t* l = (ld_t*)kmalloc(sizeof(ld_t));
  l->read_buf = (char*)kmalloc(buf_size);
  l->buf_len = buf_size;
  l->start_idx = l->cooked_idx = l->raw_idx = 0;
  l->sink = 0x0;
  l->sink_arg = 0x0;
  kthread_queue_init(&l->wait_queue);
  l->tty = makedev(DEVICE_ID_UNKNOWN, DEVICE_ID_UNKNOWN);
  set_default_termios(&l->termios);
  return l;
}

void ld_destroy(ld_t* l) {
  if (l->read_buf) {
    kfree(l->read_buf);
  }
  kfree(l);
}

static inline size_t circ_inc(ld_t* l, size_t x) {
  return (x + 1) % l->buf_len;
}

static inline size_t circ_dec(ld_t* l, size_t x) {
  if (x == 0) return l->buf_len - 1;
  else return x - 1;
}

static void cook_buffer(ld_t* l) {
  l->cooked_idx = l->raw_idx;

  // Wake up all the waiting threads.
  scheduler_wake_all(&l->wait_queue);
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

static inline bool is_ctrl(char c) {
  return !kisprint(c) && !kisspace(c);
}

// Returns the number of terminal characters the given character is rendered
// into ('a' -> 1, '\x01' -> 2, etc).
static inline int char_term_len(char c) {
  if (c == '\x7f')
    return 0;
  else if (is_ctrl(c))
    return 2;
  else return 1;
}

// Send a character to terminal, translating it if necessary.  erased_char is
// the character erased from the buffer, if any.
static void ld_term_putc(const ld_t* l, char c, char erased_char) {
  if (c == '\x7f' && l->termios.c_lflag & ICANON &&
      l->termios.c_lflag & ECHOE) {
    KASSERT_DBG(erased_char > 0);
    for (int i = 0; i < char_term_len(erased_char); ++i) {
      l->sink(l->sink_arg, '\b');
      l->sink(l->sink_arg, ' ');
      l->sink(l->sink_arg, '\b');
    }
  } else if (is_ctrl(c)) {
    l->sink(l->sink_arg, '^');
    l->sink(l->sink_arg, (c + '@') & 0x7f);
  } else {
    l->sink(l->sink_arg, c);
  }
}

void ld_provide(ld_t* l, char c) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);

  // Check for overflow.
  if (c != '\x7f' && circ_inc(l, l->raw_idx) == l->start_idx) {
    char buf[2];
    buf[0] = c;
    buf[1] = '\0';
    klogf("WARNING: ld buffer full; dropping char '%s'\n", buf);
    return;
  }

  int echo = (l->termios.c_lflag & ECHO);
  char erased_char = 0;
  bool handled = false;
  if (l->termios.c_lflag & ICANON) {
    switch (c) {
      case '\x7f':
        if (l->cooked_idx == l->raw_idx) {
          // Ignore backspace at start of line.
          return;
        }
        l->raw_idx = circ_dec(l, l->raw_idx);
        erased_char = l->read_buf[l->raw_idx];
        l->read_buf[l->raw_idx] = '#';  // DEBUG
        handled = true;
        break;

      case ASCII_EOT:
        echo = 0;
        handled = true;
        break;
    }
  }
  if (!handled && l->termios.c_lflag & ISIG) {
    switch (c) {
      // TODO(aoates): check and c_cc for these.
      case ASCII_ETX:
      case ASCII_SUB:
      case ASCII_FS:
        // Echo, but don't copy to buffer.  Clear the current buffer.
        l->start_idx = l->cooked_idx = l->raw_idx;
        handled = true;
        break;
    }
  }
  if (!handled) {
    switch (c) {
      case '\r':
      case '\f':
        die("ld cannot handle '\\r' or '\\f' characters (only '\\n')");
        break;

      case '\n':
        if (l->termios.c_lflag & ECHONL)
          echo = 1;
        // Fall through.

      default:
        l->read_buf[l->raw_idx] = c;
        l->raw_idx = circ_inc(l, l->raw_idx);
        break;
    }
  }

  // Echo it to the screen.
  if (echo) {
    ld_term_putc(l, c, erased_char);
  }

  // Cook the buffer, optionally.
  if (c == '\n' || c == ASCII_EOT || !(l->termios.c_lflag & ICANON)) {
    cook_buffer(l);
  }

  if (minor(l->tty) != DEVICE_ID_UNKNOWN && l->termios.c_lflag & ISIG) {
    int signal = SIGNULL;
    switch (c) {
      case ASCII_ETX: signal = SIGINT; break;
      case ASCII_SUB: signal = SIGTSTP; break;
      case ASCII_FS: signal = SIGQUIT; break;
    }
    if (signal != SIGNULL) {
      const tty_t* tty = tty_get(l->tty);
      KASSERT_DBG(tty != NULL);
      if (tty->session >= 0) {
        const proc_session_t* session = proc_session_get(tty->session);
        KASSERT_DBG(session->ctty == (int)minor(l->tty));
        if (session->fggrp >= 0) {
          int result = proc_force_signal_group(session->fggrp, signal);
          KASSERT_DBG(result == 0);
        }
      }
    }
  }
}

void ld_set_sink(ld_t* l, char_sink_t sink, void* arg) {
  l->sink = sink;
  l->sink_arg = arg;
}

void ld_set_tty(ld_t* l, apos_dev_t tty) {
  l->tty = tty;
}

apos_dev_t ld_get_tty(const ld_t* l) {
  return l->tty;
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

static inline size_t readable_bytes(const ld_t* l) {
  return (l->cooked_idx + l->buf_len - l->start_idx) % l->buf_len;
}

int ld_read(ld_t* l, char* buf, int n) {
  PUSH_AND_DISABLE_INTERRUPTS();

  if (minor(l->tty) != DEVICE_ID_UNKNOWN) {
    tty_t* tty = tty_get(l->tty);
    if (tty->session == proc_getsid(0) &&
        getpgid(0) != proc_session_get(tty->session)->fggrp) {
      int result = -EIO;
      if (proc_signal_deliverable(kthread_current_thread(), SIGTTIN)) {
        // TODO(aoates): should this just be regular proc_force_signal()?
        proc_force_signal_on_thread(proc_current(), kthread_current_thread(),
                                    SIGTTIN);
        result = -EINTR;
      }

      POP_INTERRUPTS();
      return result;
    }
  }

  // Note: this means that if multiple threads are blocking on an ld_read()
  // here, we could return 0 for some of them even though we didn't see an EOF!
  int result = 0;
  if (l->termios.c_lflag & ICANON) {
    if (l->start_idx == l->cooked_idx) {
      // Block until data is available.
      int wait_result = scheduler_wait_on_interruptable(&l->wait_queue, -1);
      if (wait_result == SWAIT_INTERRUPTED) result = -EINTR;
    }
  } else {
    const unsigned int tmin = l->termios.c_cc[VMIN];
    const unsigned int ttime = l->termios.c_cc[VTIME];

    if (tmin > 0 || ttime > 0) {
      if (readable_bytes(l) < tmin) {
        // First block until *any* data is available.
        while (readable_bytes(l) == 0) {
          int wait_result = scheduler_wait_on_interruptable(&l->wait_queue, -1);
          if (wait_result == SWAIT_INTERRUPTED) {
            result = -EINTR;
            break;
          }
        }
      }
      if (result == 0) {
        // Block until MIN bytes are available, or VTIME has elapsed.
        // TODO(aoates): this isn't totally correct, another thread could gobble
        // the first byte we got in the above loop (for MIN>0 && TIME>0 case)
        uint32_t now = get_time_ms();
        uint32_t timeout_end = ttime * 100;
        if (timeout_end > 0) timeout_end += now;

        while ((timeout_end == 0 || timeout_end > now) &&
               (readable_bytes(l) == 0 || readable_bytes(l) < tmin)) {
          long timeout_duration =
              (timeout_end == 0) ? -1 : (long)(timeout_end - now);
          int wait_result =
              scheduler_wait_on_interruptable(&l->wait_queue, timeout_duration);
          if (wait_result == SWAIT_INTERRUPTED) {
            result = -EINTR;
            break;
          }
          now = get_time_ms();
        }
      }
    }
  }

  if (!result) {
    // TODO(aoates): handle end-of-stream.
    result = ld_read_internal(l, buf, n);
  }

  POP_INTERRUPTS();
  return result;
}

int ld_read_async(ld_t* l, char* buf, int n) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int copied = ld_read_internal(l, buf, n);
  POP_INTERRUPTS();
  return copied;
}

int ld_write(ld_t* l, const char* buf, int n) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);

  // TODO(aoates): check if writing to the CTTY from a background process group,
  // and send SIGTTOU if the TOSTOP flag is set [termios].

  for (int i = 0; i < n; ++i) {
    l->sink(l->sink_arg, buf[i]);
  }

  return n;
}

static int ld_char_dev_read(struct char_dev* dev, void* buf, size_t len) {
  return ld_read((ld_t*)dev->dev_data, buf, len);
}

static int ld_char_dev_write(struct char_dev* dev, const void* buf,
                             size_t len) {
  return ld_write((ld_t*)dev->dev_data, buf, len);
}

void ld_init_char_dev(ld_t* l, char_dev_t* dev) {
  dev->read = &ld_char_dev_read;
  dev->write = &ld_char_dev_write;
  dev->dev_data = l;
}

void ld_get_termios(const ld_t* l, struct termios* t) {
  kmemcpy(t, &l->termios, sizeof(struct termios));
}

int ld_set_termios(ld_t* l, const struct termios* t) {
  if (t->c_iflag != 0 || t->c_oflag != 0 || t->c_cflag != CS8)
    return -EINVAL;

  if (t->c_cc[VEOL] != _POSIX_VDISABLE || t->c_cc[VKILL] != _POSIX_VDISABLE ||
      t->c_cc[VSTART] != _POSIX_VDISABLE || t->c_cc[VSTOP] != _POSIX_VDISABLE)
    return -EINVAL;

  if (t->c_lflag & ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG))
    return -EINVAL;

  kmemcpy(&l->termios, t, sizeof(struct termios));

  return 0;
}
