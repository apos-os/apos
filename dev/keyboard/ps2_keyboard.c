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
#include "common/kstring.h"
#include "common/kprintf.h"

#include "dev/ps2.h"
#include "dev/keyboard/keyboard.h"
#include "dev/keyboard/ps2_scancodes.h"

#define PS2_DATA_TIMEOUT 10000

static vkeyboard_t* g_vkbd = 0x0;

// Given a buffer of scancodes, process it and potentially generate a keypress.
// Returns the new (potentially truncated) buffer length.
static int process_scancode_buffer(uint8_t* buf, int len) {
  if (len > 3) {
    klogf("WARNING: unknown long scancode sequence (%d bytes)\n", len);
  }

  uint8_t c = 0;
  bool is_up_evt = 0;
  bool is_extended = 0;
  bool done = 0;

  for (int i = 0; i < len; ++i) {
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
    return len;
  }

  uint32_t keycode = ps2_convert_scancode(c, is_extended);
  if (keycode == NONE) {
    klogf("WARNING: ignoring unknown scancode: 0x%x (extended: %d)\n",
        c, is_extended);
  } else if (g_vkbd) {
    vkeyboard_send_keycode(g_vkbd, keycode, is_up_evt);
  }

  return 0;
}

static void irq_handler(void* arg) {
  static uint8_t scancode_buffer[10];
  static int buf_idx = 0;

  uint8_t c;
  if (!ps2_read_byte_async(PS2_PORT1, &c, PS2_DATA_TIMEOUT)) {
    klogf("WARNING: expected data byte from PS/2 keyboard controller "
          "but timed out.\n");
    return;
  }
  KASSERT(buf_idx < 9);
  scancode_buffer[buf_idx++] = c;

  // Process the buffer.
  buf_idx = process_scancode_buffer(scancode_buffer, buf_idx);
}

int ps2_keyboard_init(vkeyboard_t* vkbd) {
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
