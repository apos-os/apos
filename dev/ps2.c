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

#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"

#include "dev/irq.h"

#define CTRL_DATA_PORT 0x60
#define CTRL_STATUS_PORT 0x64
#define CTRL_CMD_PORT 0x64

// Bits for the controller status register.
#define CTRL_STATUS_OBF 0x01  // Must be set before reading data
#define CTRL_STATUS_IBF 0x02  // Must be clear before writing data or commands
#define CTRL_STATUS_SYSTEM 0x04
#define CTRL_STATUS_COMMAND 0x08
#define CTRL_STATUS_TIMEOUT_ERR 0x40
#define CTRL_STATUS_PARITY_ERR 0x80

// Controller config bits.
#define CTRL_CFG_INT1    0x01
#define CTRL_CFG_INT2    0x02
#define CTRL_CFG_SYSTEM  0x04
#define CTRL_CFG_CLOCK1  0x10
#define CTRL_CFG_CLOCK2  0x20
#define CTRL_CFG_TRANS1  0x40

// Controller commands.
#define CTRL_CMD_READ_CONFIG     0x20
#define CTRL_CMD_WRITE_CONFIG    0x60

#define CTRL_CMD_DISABLE_PORT1   0xAD
#define CTRL_CMD_ENABLE_PORT1    0xAE
#define CTRL_CMD_DISABLE_PORT2   0xA7
#define CTRL_CMD_ENABLE_PORT2    0xA8

#define CTRL_CMD_SELF_TEST       0xAA
#define CTRL_CMD_TEST_PORT1      0xAB
#define CTRL_CMD_TEST_PORT2      0xA9

// Values returned by the controller self-test.
#define CTRL_SELF_TEST_PASS      0x55
#define CTRL_SELF_TEST_FAIL      0xFC

// Values returned by the controller port tests.
#define CTRL_PORT_TEST_PASS      0x00

// PS/2 (not controller) commands.
#define PS2_CMD_RESET             0xFF
#define PS2_CMD_DISABLE_SCANNING  0xF5
#define PS2_CMD_ENABLE_SCANNING   0xF4
#define PS2_CMD_IDENTIFY          0xF2

#define PS2_ACK           0xFA
#define PS2_RESET_FAIL    0xFC

// Setting and clearing bits.
#define IS_SET(a, mask) ((a) & (mask))
#define SET(a, mask) ((a) | (mask))
#define CLEAR(a, mask) ((a) & ~(mask))


#define DEVICE_UNKNOWN 0
#define DEVICE_KEYBOARD 1
static int g_port1_device = DEVICE_UNKNOWN;

static void send_cmd(uint8_t cmd) {
  outb(CTRL_CMD_PORT, cmd);
}

inline static uint8_t get_status() {
  return inb(CTRL_STATUS_PORT);
}

// Blocks until data is available.
static uint8_t read_data() {
  // Wait for OBF to be set.
  uint8_t status = get_status();
  while (!IS_SET(status, CTRL_STATUS_OBF)) {
    status = get_status();
  }
  return inb(CTRL_DATA_PORT);
}

// Returns 1 if data is read, and (if so) puts it in data_out.
// Loops up to timeout times before giving up.
static int read_data_async(uint8_t* data_out, int timeout) {
  // Wait for OBF to be set.
  uint8_t status = get_status();
  while (!IS_SET(status, CTRL_STATUS_OBF) && timeout > 0) {
    status = get_status();
    timeout--;
  }
  if (IS_SET(status, CTRL_STATUS_OBF)) {
    *data_out = inb(CTRL_DATA_PORT);
    return 1;
  }
  return 0;
}

static void write_data(uint8_t data) {
  // Wait for IBF to be clear.
  uint8_t status = get_status();
  while (IS_SET(status, CTRL_STATUS_IBF)) {
    status = get_status();
  }
  outb(CTRL_DATA_PORT, data);
}

static const char* status_str(uint8_t status) {
  static char buf[256];
  ksprintf(buf, "0x%x [ ", status);
  if (IS_SET(status, CTRL_STATUS_OBF)) kstrcat(buf, "OBF ");
  if (IS_SET(status, CTRL_STATUS_IBF)) kstrcat(buf, "IBF ");
  if (IS_SET(status, CTRL_STATUS_SYSTEM)) kstrcat(buf, "SYS ");
  if (IS_SET(status, CTRL_STATUS_COMMAND)) kstrcat(buf, "CMD ");
  if (IS_SET(status, CTRL_STATUS_TIMEOUT_ERR)) kstrcat(buf, "TIMEOUT ");
  if (IS_SET(status, CTRL_STATUS_PARITY_ERR)) kstrcat(buf, "PARITY ");
  kstrcat(buf, "]");
  return buf;
}

static const char* config_str(uint8_t config) {
  static char buf[256];
  ksprintf(buf, "0x%x [ ", config);
  if (IS_SET(config, CTRL_CFG_INT1)) kstrcat(buf, "INT1 ");
  if (IS_SET(config, CTRL_CFG_INT2)) kstrcat(buf, "INT2 ");
  if (IS_SET(config, CTRL_CFG_SYSTEM)) kstrcat(buf, "SYS ");
  if (IS_SET(config, CTRL_CFG_CLOCK1)) kstrcat(buf, "CLK1 ");
  if (IS_SET(config, CTRL_CFG_CLOCK2)) kstrcat(buf, "CLK2 ");
  if (IS_SET(config, CTRL_CFG_TRANS1)) kstrcat(buf, "TRANS1 ");
  kstrcat(buf, "]");
  return buf;
}

static int controller_init() {
  klogf("  initializing controller...\n");
  uint8_t status = get_status();
  klogf("  controller status: %s\n", status_str(status));
  send_cmd(CTRL_CMD_READ_CONFIG);
  uint8_t config = read_data();
  klogf("  controller config: %s\n", config_str(config));

  // Disable ports.
  klogf("  disabling ports...\n");
  send_cmd(CTRL_CMD_DISABLE_PORT1);
  send_cmd(CTRL_CMD_DISABLE_PORT2);

  // Flush the output buffer.
  klogf("  flushing output buffer...\n");
  uint8_t data;
  read_data_async(&data, 0);

  // TODO(aoates): properly handle 2 channels.

  // Send new config.  Disable interrupts and translation.
  config = SET(config, CTRL_CFG_INT1);
  config = CLEAR(config, CTRL_CFG_INT2);
  config = CLEAR(config, CTRL_CFG_TRANS1);
  klogf("  sending new config: %s\n", config_str(config));
  send_cmd(CTRL_CMD_WRITE_CONFIG);
  write_data(config);

  // Do controller self-test.
  klogf("  controller self test: ");
  send_cmd(CTRL_CMD_SELF_TEST);
  uint8_t result = read_data();
  if (result == CTRL_SELF_TEST_PASS) {
    klogf("PASSED\n");
  } else if (result == CTRL_SELF_TEST_FAIL) {
    klogf("FAILED\n");
    return 0;
  } else {
    klogf("PANIC: unknown device self-test response code: %x\n", result);
    KASSERT(0);
  }

  // Do port test.
  // TODO(aoates): test for port2, enable/disable, etc.
  klogf("  port1 test: ");
  send_cmd(CTRL_CMD_TEST_PORT1);
  result = read_data();
  if (result == CTRL_PORT_TEST_PASS) {
    klogf("PASSED\n");
  } else {
    klogf("FAILED (0x%x)\n", result);
    return 0;
  }

  // Enable devices.
  klogf("  enabling port1...\n");
  send_cmd(CTRL_CMD_ENABLE_PORT1);

  // TODO(aoates): enable IRQ once we want them.
  return 1;
}

static int device_init() {
  // Reset the device.
  klogf("  resetting port1 device...\n");
  write_data(PS2_CMD_RESET);
  uint8_t result;
  if (!read_data_async(&result, 100)) {
    klogf("  reset FAILED (no response)\n");
    return 0;
  } else if (result != PS2_ACK) {
    klogf("  reset FAILED (result: 0x%x)\n", result);
    return 0;
  }

  // Identify it as a keyboard (hopefully).
  klogf("  identifying port1 device...\n");
  write_data(PS2_CMD_DISABLE_SCANNING);

  result = read_data();
  int t = 10;
  while (result != PS2_ACK && t > 0) {
    result = read_data();
    t--;
  }
  if (result != PS2_ACK) {
    klogf("  disable scan failed: 0x%x\n", result);
    return 0;
  }
  write_data(PS2_CMD_IDENTIFY);
  result = read_data();
  if (result != PS2_ACK) {
    klogf("  identify failed: 0x%x\n", result);
    return 0;
  }

  // Read 1 or (maybe) 2 bytes of device ID.
  uint8_t type1, type2;
  type1 = read_data();
  result = read_data_async(&type2, 100);
  char buf[50];
  if (result) {
    ksprintf(buf, "0x%x 0x%x", (uint32_t)type1, (uint32_t)type2);
  } else {
    ksprintf(buf, "0x%x", (uint32_t)type1);
  }
  klogf("  device ID: %s\n", buf);

  if (type1 == 0xAB && type2 == 0x83) {
    klogf("  device identified as keyboard\n");
    g_port1_device = DEVICE_KEYBOARD;
  } else {
    klogf("  device identified as unknown type\n");
    g_port1_device = DEVICE_UNKNOWN;
  }

  // Re-enable scanning.
  write_data(PS2_CMD_ENABLE_SCANNING);
  result = read_data();
  if (result != PS2_ACK) {
    klogf("  re-enable scan failed: 0x%x\n", result);
    return 0;
  }

  // Enable interrupts.
  send_cmd(CTRL_CMD_READ_CONFIG);
  uint8_t config = read_data();
  config = SET(config, CTRL_CFG_INT1);
  klogf("  enabling interrupt...\n");
  send_cmd(CTRL_CMD_WRITE_CONFIG);
  write_data(config);

  return 1;
}

uint8_t read_char() {
  uint8_t c = read_data();
  switch (c) {
    case 0xF0: read_data(); return '?';
    case 0xE0: read_data(); return '?';
    case 0xE1: read_data(); read_data(); return '?';
    case 0x1C: return 'A';
    case 0x32: return 'B';
    case 0x21: return 'C';
    case 0x23: return 'D';
    case 0x24: return 'E';
    default: return '?';
  }
}

void keyboard_interrupt() {
  char buf[2];
  buf[1] = '\0';
  buf[0] = read_char();
  klogf("keyboard: %s\n", buf);
}

void ps2_init() {
  klogf("Initializing PS/2 controller...\n");
  if (!controller_init()) {
    klogf("  aborting initalization\n");
    return;
  }

  if (!device_init()) {
    klogf("  aborting initalization\n");
    return;
  }
  klogf("  finished PS/2 initalization!\n");

  register_irq_handler(IRQ1, &keyboard_interrupt);
}
