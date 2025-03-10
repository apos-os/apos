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
#include "memory/kmalloc.h"
#include "dev/char_dev.h"
#include "dev/ld.h"
#include "dev/tty_util.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "user/include/apos/termios.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/poll.h"

// TODO(aoates): I think per the spec this should just _ignore_ unsupported
// flags rather than reject them.
#define SUPPORTED_OFLAGS (ONLCR)

struct ld {
  kspinlock_t lock;

  // Circular buffer of characters ready to be read.  Indexed by {start, cooked,
  // raw}_idx, which refer to the first character, the end of the cooked region,
  // and the end of the raw region respectively.
  //  start_idx <= cooked_idx <= raw_idx
  // (subject to circular index rollover).
  char* read_buf GUARDED_BY(&lock);
  int buf_len GUARDED_BY(&lock);
  size_t start_idx GUARDED_BY(&lock);
  size_t cooked_idx GUARDED_BY(&lock);
  size_t raw_idx GUARDED_BY(&lock);

  // The character sink for echoing and writing.
  char_sink_t sink;
  void* sink_arg;

  // Threads that are waiting for cooked data to be available in the buffer.
  kthread_queue_t wait_queue GUARDED_BY(&lock);

  // TODO(SMP): synchronize access to the TTY (if necessary).
  apos_dev_t tty;
  struct ktermios termios GUARDED_BY(&lock);

  pollable_t poll_event;
};

// Note: keep this in sync with the version in getty.c.
static void set_default_termios(struct ktermios* t) {
  t->c_iflag = 0;
  t->c_oflag = ONLCR;
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

static void ld_flush_input(ld_t* l) REQUIRES(l->lock) {
  l->start_idx = l->cooked_idx = l->raw_idx;
}

ld_t* ld_create(int buf_size) {
  ld_t* l = (ld_t*)kmalloc(sizeof(ld_t));
  kspin_constructor(&l->lock);
  l->lock = KSPINLOCK_NORMAL_INIT;
  l->read_buf = (char*)kmalloc(buf_size);
  l->buf_len = buf_size;
  l->start_idx = l->cooked_idx = l->raw_idx = 0;
  l->sink = 0x0;
  l->sink_arg = 0x0;
  kthread_queue_init(&l->wait_queue);
  l->tty = kmakedev(DEVICE_ID_UNKNOWN, DEVICE_ID_UNKNOWN);
  set_default_termios(&l->termios);
  poll_init_event(&l->poll_event);
  return l;
}

void ld_destroy(ld_t* l) {
  kspin_destructor(&l->lock);
  if (l->read_buf) {
    kfree(l->read_buf);
  }
  kfree(l);
}

static inline size_t circ_inc(ld_t* l, size_t x) REQUIRES(l->lock) {
  return (x + 1) % l->buf_len;
}

static inline size_t circ_dec(ld_t* l, size_t x) REQUIRES(l->lock) {
  if (x == 0) return l->buf_len - 1;
  else return x - 1;
}

static int ld_get_poll_events(const ld_t* l) REQUIRES(l->lock) {
  int events = KPOLLOUT;  // Always writable.
  if (l->start_idx != l->cooked_idx) events |= KPOLLIN | KPOLLRDNORM;
  return events;
}

static void cook_buffer(ld_t* l) REQUIRES(l->lock) {
  l->cooked_idx = l->raw_idx;

  // Wake up all the waiting threads.
  scheduler_wake_all(&l->wait_queue);

  poll_trigger_event(&l->poll_event, ld_get_poll_events(l));
}

void log_state(ld_t* l) {
  klogf("ld state:\n");
  kspin_lock(&l->lock);
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
  kspin_unlock(&l->lock);
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
static void ld_term_putc(const ld_t* l, ktcflag_t lflag, ktcflag_t oflag,
                         char c, char erased_char, bool is_echo)
    EXCLUDES(l->lock) {
  KASSERT(!kspin_is_held(&l->lock));
  // TODO(aoates): use ECHOCTL.
  if (is_echo && c == '\x7f' && (lflag & ICANON) && (lflag & ECHOE)) {
    KASSERT_DBG(erased_char > 0);
    for (int i = 0; i < char_term_len(erased_char); ++i) {
      l->sink(l->sink_arg, '\b');
      l->sink(l->sink_arg, ' ');
      l->sink(l->sink_arg, '\b');
    }
  } else if (c == '\n' && (oflag & ONLCR)) {
    l->sink(l->sink_arg, '\r');
    l->sink(l->sink_arg, '\n');
  } else if (is_echo && is_ctrl(c)) {
    l->sink(l->sink_arg, '^');
    l->sink(l->sink_arg, (c + '@') & 0x7f);
  } else {
    l->sink(l->sink_arg, c);
  }
}

void ld_provide(ld_t* l, char c) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);
  kspin_lock(&l->lock);

  // Check for overflow.
  if (c != '\x7f' && circ_inc(l, l->raw_idx) == l->start_idx) {
    kspin_unlock(&l->lock);
    char buf[2];
    buf[0] = c;
    buf[1] = '\0';
    klogf("WARNING: ld buffer full; dropping char '%s'\n", buf);
    return;
  }

  int echo = (l->termios.c_lflag & ECHO);
  char erased_char = 0;
  char echo_char = c;  // The character to be echoed.
  bool handled = false;
  if (l->termios.c_lflag & ICANON) {
    if (c == '\x7f') {
      if (l->cooked_idx == l->raw_idx) {
        // Ignore backspace at start of line.
        kspin_unlock(&l->lock);
        return;
      }
      l->raw_idx = circ_dec(l, l->raw_idx);
      erased_char = l->read_buf[l->raw_idx];
      l->read_buf[l->raw_idx] = '#';  // DEBUG
      handled = true;
    } else if (c == l->termios.c_cc[VEOF]) {
      echo = 0;
      handled = true;
    }
  }
  if (!handled && l->termios.c_lflag & ISIG) {
    if (c == l->termios.c_cc[VINTR] || c == l->termios.c_cc[VSUSP] ||
        c == l->termios.c_cc[VQUIT]) {
      if (!(l->termios.c_lflag & NOFLSH)) {
        // Echo, but don't copy to buffer.  Clear the current buffer.
        ld_flush_input(l);
      }
      handled = true;
    }
  }
  if (!handled) {
    switch (c) {
      case '\r':
        // TODO(aoates): obey ICRNL.
        c = '\n';  // Treat as a newline.
        // If ONLCR, send '\n' to ld_term_putc(), which will expand to \r\n.
        // Otherwise echo the literal '\r' back out.
        if (l->termios.c_oflag & ONLCR) {
          echo_char = '\n';
        }
        // Fall through.

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

  // Cook the buffer, optionally.
  if (c == '\n' || c == l->termios.c_cc[VEOF] ||
      !(l->termios.c_lflag & ICANON)) {
    cook_buffer(l);
  }

  if (kminor(l->tty) != DEVICE_ID_UNKNOWN && l->termios.c_lflag & ISIG) {
    int signal = APOS_SIGNULL;
    if (c == l->termios.c_cc[VINTR]) signal = SIGINT;
    else if (c == l->termios.c_cc[VSUSP]) signal = SIGTSTP;
    else if (c == l->termios.c_cc[VQUIT]) signal = SIGQUIT;

    if (signal != APOS_SIGNULL) {
      const tty_t* tty = tty_get(l->tty);
      KASSERT_DBG(tty != NULL);
      kspin_lock(&g_proc_table_lock);
      if (tty->session >= 0) {
        const proc_session_t* session = proc_session_get(tty->session);
        KASSERT_DBG(session->ctty == (int)kminor(l->tty));

        if (session->fggrp >= 0) {
          proc_group_t* pgroup = proc_group_get(session->fggrp);
          int result = proc_force_signal_group_locked(pgroup, signal);
          KASSERT_DBG(result == 0);
        }
      }
      kspin_unlock(&g_proc_table_lock);
    }
  }
  ktcflag_t lflag = l->termios.c_lflag;
  ktcflag_t oflag = l->termios.c_oflag;
  kspin_unlock(&l->lock);

  // Echo it to the screen.
  if (echo) {
    ld_term_putc(l, lflag, oflag, echo_char, erased_char, /* is_echo */ true);
  }
}

void ld_set_sink(ld_t* l, char_sink_t sink, void* arg) {
  // TODO(aoates): ideally, assert that this is only ever set once outside of
  // test code (or rewrite the tests to make this invariant).
  l->sink = sink;
  l->sink_arg = arg;
}

void ld_set_tty(ld_t* l, apos_dev_t tty) {
  l->tty = tty;
}

apos_dev_t ld_get_tty(const ld_t* l) {
  return l->tty;
}

static int ld_do_read(ld_t* l, char* buf, int n) REQUIRES(l->lock) {
  KASSERT_DBG(kspin_is_held(&l->lock));
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

static inline size_t readable_bytes(const ld_t* l) REQUIRES(l->lock) {
  return (l->cooked_idx + l->buf_len - l->start_idx) % l->buf_len;
}

// Block until ld_read() should return, as determined by the ld's configuration.
static int ld_read_block(ld_t* l) REQUIRES(l->lock) {
  KASSERT_DBG(kspin_is_held(&l->lock));
  if (l->termios.c_lflag & ICANON) {
    // Note: this means that if multiple threads are blocking on an ld_read()
    // here, we could return 0 for some of them even though we didn't see an
    // EOF!
    if (l->start_idx == l->cooked_idx) {
      // Block until data is available.
      int wait_result =
          scheduler_wait_on_splocked(&l->wait_queue, -1, &l->lock);
      if (wait_result == SWAIT_INTERRUPTED) return -EINTR;
    }
  } else {
    const unsigned int tmin = l->termios.c_cc[VMIN];
    const unsigned int ttime = l->termios.c_cc[VTIME];

    if (tmin > 0 || ttime > 0) {
      if (readable_bytes(l) < tmin) {
        // First block until *any* data is available.
        while (readable_bytes(l) == 0) {
          int wait_result =
              scheduler_wait_on_splocked(&l->wait_queue, -1, &l->lock);
          if (wait_result == SWAIT_INTERRUPTED) return -EINTR;
        }
      }
      // Block until MIN bytes are available, or VTIME has elapsed.
      // TODO(aoates): this isn't totally correct, another thread could gobble
      // the first byte we got in the above loop (for MIN>0 && TIME>0 case)
      apos_ms_t now = get_time_ms();
      apos_ms_t timeout_end = ttime * 100;
      if (timeout_end > 0) timeout_end += now;

      while ((timeout_end == 0 || timeout_end > now) &&
             (readable_bytes(l) == 0 || readable_bytes(l) < tmin)) {
        long timeout_duration =
            (timeout_end == 0) ? -1 : (long)(timeout_end - now);
        int wait_result = scheduler_wait_on_splocked(
            &l->wait_queue, timeout_duration, &l->lock);
        if (wait_result == SWAIT_INTERRUPTED) return -EINTR;
        now = get_time_ms();
      }
    }
  }

  return 0;
}

int ld_read(ld_t* l, char* buf, int n, int flags) {
  kspin_lock(&l->lock);

  if (kminor(l->tty) != DEVICE_ID_UNKNOWN) {
    tty_t* tty = tty_get(l->tty);
    int result = tty_check_read(tty);
    if (result) {
      kspin_unlock(&l->lock);
      return result;
    }
  }

  int result = 0;
  if (!(flags & VFS_O_NONBLOCK)) {
    result = ld_read_block(l);
  }

  if (!result) {
    result = ld_do_read(l, buf, n);
  }
  if (result == 0) result = -EAGAIN;

  kspin_unlock(&l->lock);
  return result;
}

int ld_write(ld_t* l, const char* buf, int n) {
  KASSERT(l != 0x0);
  KASSERT(l->sink != 0x0);

  kspin_lock(&l->lock);
  if (l->termios.c_lflag & TOSTOP && kminor(l->tty) != DEVICE_ID_UNKNOWN) {
    int result = tty_check_write(tty_get(l->tty));
    if (result) {
      kspin_unlock(&l->lock);
      return result;
    }
  }

  ktcflag_t lflag = l->termios.c_lflag;
  ktcflag_t oflag = l->termios.c_oflag;
  kspin_unlock(&l->lock);

  for (int i = 0; i < n; ++i) {
    ld_term_putc(l, lflag, oflag, buf[i], ' ', /* is_echo */ false);
  }

  return n;
}

static int ld_char_dev_read(struct char_dev* dev, void* buf, size_t len,
                            int flags) {
  return ld_read((ld_t*)dev->dev_data, buf, len, flags);
}

// For some reason, adding the flags parameter above causes a 1.5x-2x slowdown,
// though I'm not sure why.  Adding a little bit of extra code fixes it.
// TODO(aoates): remove this when not needed any longer.
void _ld_pad(void) {}

static int ld_char_dev_write(struct char_dev* dev, const void* buf,
                             size_t len, int flags) {
  return ld_write((ld_t*)dev->dev_data, buf, len);
}

static int ld_char_dev_poll(struct char_dev* dev, short event_mask,
                            poll_state_t* poll) {
  ld_t* l = (ld_t*)dev->dev_data;
  kspin_lock(&l->lock);
  int events = ld_get_poll_events(l) & event_mask;
  kspin_unlock(&l->lock);
  if (events || !poll) return events;

  return poll_add_event(poll, &l->poll_event, event_mask);
}

void ld_init_char_dev(ld_t* l, char_dev_t* dev) {
  dev->read = &ld_char_dev_read;
  dev->write = &ld_char_dev_write;
  dev->poll = &ld_char_dev_poll;
  dev->dev_data = l;
}

void ld_get_termios(const ld_t* l, struct ktermios* t) {
  ld_t* l_mut = (ld_t*)l;
  kspin_lock(&l_mut->lock);
  kmemcpy(t, &l->termios, sizeof(struct ktermios));
  kspin_unlock(&l_mut->lock);
}

int ld_set_termios(ld_t* l, int optional_actions, const struct ktermios* t) {
  if (t->c_iflag != 0 || ((t->c_oflag & ~SUPPORTED_OFLAGS) != 0) ||
      t->c_cflag != CS8)
    return -EINVAL;

  if (t->c_cc[VEOL] != _POSIX_VDISABLE || t->c_cc[VKILL] != _POSIX_VDISABLE ||
      t->c_cc[VSTART] != _POSIX_VDISABLE || t->c_cc[VSTOP] != _POSIX_VDISABLE)
    return -EINVAL;

  if (t->c_lflag &
      ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG | NOFLSH | TOSTOP))
    return -EINVAL;

  if (optional_actions != TCSANOW && optional_actions != TCSADRAIN &&
      optional_actions != TCSAFLUSH)
    return -EINVAL;

  kspin_lock(&l->lock);
  if (kminor(l->tty) != DEVICE_ID_UNKNOWN) {
    int result = tty_check_write(tty_get(l->tty));
    if (result) {
      kspin_unlock(&l->lock);
      return result;
    }
  }

  if (optional_actions == TCSAFLUSH)
    ld_flush_input(l);

  kmemcpy(&l->termios, t, sizeof(struct ktermios));
  kspin_unlock(&l->lock);

  return 0;
}

int ld_drain(ld_t* l) {
  if (kminor(l->tty) != DEVICE_ID_UNKNOWN) {
    int result = tty_check_write(tty_get(l->tty));
    if (result) return result;
  }

  return 0;
}

int ld_flush(ld_t* l, int queue_selector) {
  if (queue_selector != TCIFLUSH && queue_selector != TCOFLUSH &&
      queue_selector != TCIOFLUSH)
    return -EINVAL;

  if (kminor(l->tty) != DEVICE_ID_UNKNOWN) {
    int result = tty_check_write(tty_get(l->tty));
    if (result) return result;
  }

  if (queue_selector == TCIFLUSH || queue_selector == TCIOFLUSH) {
    kspin_lock(&l->lock);
    ld_flush_input(l);
    kspin_unlock(&l->lock);
  }

  return 0;
}
