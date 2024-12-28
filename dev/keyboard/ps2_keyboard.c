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

#include "arch/dev/irq.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "proc/spinlock.h"
#include "proc/tasklet.h"

#include "dev/ps2.h"
#include "dev/keyboard/keyboard.h"
#include "dev/keyboard/ps2_scancodes.h"

#define PS2_DATA_TIMEOUT 10000

#define PS2_SCANCODE_BUF_SIZE 100

static vkeyboard_t* g_vkbd = 0x0;
static uint8_t g_scancode_buf[PS2_SCANCODE_BUF_SIZE];
static int g_scancode_buf_len = 0;
static kspinlock_intsafe_t g_scancode_buf_lock;
static tasklet_t g_ps2_tasklet;

typedef struct {
  uint32_t keycode;
  bool is_up_event;
  bool is_extended;
} ps2_kbd_event_t;

// Given a buffer of scancodes, process it and potentially generate a keypress.
// Returns the start of the unprocessed portion of the buffer (zero if nothing
// was consumed).
static int process_scancode_buffer(uint8_t* buf, int len, ps2_kbd_event_t* event) {
  uint8_t c = 0;
  bool is_up_evt = 0;
  bool is_extended = 0;
  bool done = 0;

  int i;
  for (i = 0; i < len && !done; ++i) {
    switch (buf[i]) {
      case 0xE0:
        is_extended = true;
        break;

      case 0xF0:
        is_up_evt = true;
        break;

      default:
        c = buf[i];
        done = true;
        break;
    }
  }

  if (!done) {
    return 0;
  }

  event->keycode = ps2_convert_scancode(c, is_extended);
  if (event->keycode == NONE) {
    klogf("WARNING: ignoring unknown scancode: 0x%x (extended: %d)\n",
        c, is_extended);
  } else {
    event->is_up_event = is_up_evt;
    event->is_extended = is_extended;
  }

  return i;
}

static void process_scancodes_tasklet(tasklet_t* tl, void* arg) {
  ps2_kbd_event_t event;
  kspin_lock_int(&g_scancode_buf_lock);
  int consumed =
      process_scancode_buffer(g_scancode_buf, g_scancode_buf_len, &event);

  if (consumed) {
    for (int i = consumed; i < g_scancode_buf_len; ++i) {
      g_scancode_buf[i - consumed] = g_scancode_buf[i];
    }
    g_scancode_buf_len -= consumed;
  }
  kspin_unlock_int(&g_scancode_buf_lock);

  if (consumed && event.keycode != NONE && g_vkbd) {
    vkeyboard_send_keycode(g_vkbd, event.keycode, event.is_up_event);
  }
}

static void irq_handler(void* arg) {
  uint8_t c;
  if (!ps2_read_byte_async(PS2_PORT1, &c, PS2_DATA_TIMEOUT)) {
    klogf("WARNING: expected data byte from PS/2 keyboard controller "
          "but timed out.\n");
    return;
  }
  KASSERT(g_scancode_buf_len < PS2_SCANCODE_BUF_SIZE);
  g_scancode_buf[g_scancode_buf_len++] = c;

  tasklet_schedule(&g_ps2_tasklet);
}

int ps2_keyboard_init(vkeyboard_t* vkbd) {
  g_scancode_buf_lock = KSPINLOCK_INTERRUPT_SAFE_INIT;
  tasklet_init(&g_ps2_tasklet, &process_scancodes_tasklet, NULL);

  if (ps2_get_device_type(PS2_PORT1) != PS2_DEVICE_KEYBOARD) {
    klogf("keyboard initalization FAILED (no keyboard found on port1)\n");
    return 0;
  }

  // TODO(aoates): we should probably verify it's in scanset 2.

  register_irq_handler(IRQ1, &irq_handler, 0x0);
  ps2_enable_interrupts(PS2_PORT1);

  g_vkbd = vkbd;
  return 1;
}
