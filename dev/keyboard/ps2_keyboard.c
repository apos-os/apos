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
#include "common/kprintf.h"

#include "dev/ps2.h"
#include "dev/irq.h"
#include "dev/keyboard/keyboard.h"
#include "dev/keyboard/ps2_scancodes.h"

#define PS2_DATA_TIMEOUT 1000000

static vkeyboard_t* g_vkbd = 0x0;

static void irq_handler() {
  uint8_t c;
  uint8_t is_up_evt = 0;
  uint8_t is_extended = 0;
  uint8_t done = 0;

  while (!done) {
    if (!ps2_read_byte_async(PS2_PORT1, &c, PS2_DATA_TIMEOUT)) {
      klogf("WARNING: expected data byte from PS/2 keyboard controller "
            "but timed out.\n");
      return;
    }
    switch (c) {
      case 0xE0:
        is_extended = 1;
        continue;

      case 0xF0:
        is_up_evt = 1;
        continue;

      default:
        done = 1;
        break;
    }
  }

  uint32_t keycode = ps2_convert_scancode(c, is_extended);
  if (keycode == NONE) {
    klogf("WARNING: ignoring unknown scancode: 0x%x (extended: %d)\n",
        c, is_extended);
  } else if (g_vkbd) {
    vkeyboard_send_keycode(g_vkbd, keycode, is_up_evt);
  }
}

int ps2_keyboard_init(vkeyboard_t* vkbd) {
  if (ps2_get_device_type(PS2_PORT1) != PS2_DEVICE_KEYBOARD) {
    klogf("keyboard initalization FAILED (no keyboard found on port1)\n");
    return 0;
  }

  // TODO(aoates): we should probably verify it's in scanset 2.

  register_irq_handler(IRQ1, &irq_handler);
  ps2_enable_interrupts(PS2_PORT1);

  g_vkbd = vkbd;
  return 1;
}
