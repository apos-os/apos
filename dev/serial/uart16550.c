// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "dev/serial/uart16550.h"

#include "arch/dev/irq.h"
#include "common/circbuf.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/char_dev.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/interrupts.h"
#include "dev/interrupts.h"
#include "dev/io.h"
#include "dev/ld.h"
#include "dev/serial/serial.h"
#include "dev/tty.h"
#include "memory/kmalloc.h"
#include "proc/defint.h"
#include "proc/spinlock.h"

#define LEGACY_COM1_IOPORT_BASE 0x3f8
#define LEGACY_COM1_INTERRUPT 4

#define U16550_REG_DATA 0  // Data rx and tx
#define U16550_REG_IE 1    // Interrupt enable
#define U16550_REG_LINE_STATUS 5

#define U16550_LSR_DR 1

#define U16550_IE_DREADY 1

#define BUFLEN 100
#define LD_BUF_SIZE 1024

typedef struct {
  // Parameters for talking to the device.
  devio_t io;
  irq_t interrupt;

  // Internal state of the serial device.
  circbuf_t buf;
  char buf_data[BUFLEN];
  ld_t* ld;
  apos_dev_t cdev;
  kspinlock_intsafe_t lock;
  bool defint_queued;
} u16550_t;

static void uart_defint(void* arg);

static void uart_interrupt(void* arg) {
  u16550_t* uart = (u16550_t*)arg;
  uint8_t status = io_read8(uart->io, U16550_REG_LINE_STATUS);
  bool data = false;
  while (status & U16550_LSR_DR) {
    data = true;
    uint8_t data = io_read8(uart->io, U16550_REG_DATA);
    if (circbuf_write(&uart->buf, &data, 1) != 1) {
      klogf("warning: U16550 dropping char (0x%x)\n", data);
      return;
    }
    status = io_read8(uart->io, U16550_REG_LINE_STATUS);
  }

  if (data && !uart->defint_queued) {
    uart->defint_queued = true;
    defint_schedule(uart_defint, uart);
  }
}

#define DEFINT_BUFSIZE 10
static void uart_defint(void* arg) {
  u16550_t* uart = (u16550_t*)arg;
  char buf[DEFINT_BUFSIZE];

  ssize_t bytes;
  do {
    kspin_lock_int(&uart->lock);
    bytes = circbuf_read(&uart->buf, &buf, DEFINT_BUFSIZE);
    uart->defint_queued = false;  // New data could come in now.
    kspin_unlock_int(&uart->lock);
    for (ssize_t i = 0; i < bytes; ++i) {
      // TODO(aoates): doing this char by char seems bad, should we pass more?
      ld_provide(uart->ld, buf[i]);
    }
  } while (bytes > 0);
}

static void uart_putc(void* arg, char c) {
  u16550_t* uart = (u16550_t*)arg;
  kspin_lock_int(&uart->lock);
  // TODO(aoates): wait for the transmit ready bit to be set (either blocking
  // the thread or waiting for an interrupt).
  io_write8(uart->io, U16550_REG_DATA, c);
  kspin_unlock_int(&uart->lock);
}

// TODO(aoates): create an abstraction for a "raw" character device (e.g. serial
// port, or PS2+vterm), and have the TTY creation code take that and entirely
// subsume the LD inside it.
static int u16550_create_internal(u16550_t* uart, apos_dev_t* dev) {
  circbuf_init(&uart->buf, &uart->buf_data, BUFLEN);
  uart->lock = KSPINLOCK_INTERRUPT_SAFE_INIT;
  uart->defint_queued = false;

  uart->ld = ld_create(LD_BUF_SIZE);
  ld_set_sink(uart->ld, &uart_putc, uart);
  uart->cdev = tty_create(uart->ld);
  *dev = uart->cdev;
  register_irq_handler(uart->interrupt, &uart_interrupt, uart);

  uint8_t val = io_read8(uart->io, U16550_REG_IE);
  val |= U16550_IE_DREADY;
  io_write8(uart->io, U16550_REG_IE, val);
  return 0;
}

int u16550_create_legacy(apos_dev_t* dev) {
  u16550_t* uart = (u16550_t*)kmalloc(sizeof(u16550_t));
  if (!uart) {
    return -ENOMEM;
  }

  // TODO(aoates): make this /dev/ttyS rather than /dev/tty.
  uart->io.type = IO_PORT;
  uart->io.base = LEGACY_COM1_IOPORT_BASE;
  uart->interrupt = LEGACY_COM1_INTERRUPT;
  return u16550_create_internal(uart, dev);
}

int u16550_driver(const dt_tree_t* tree, const dt_node_t* dtnode,
                  const char* node_path, dt_driver_info_t* driver) {
  // TODO(aoates): handle 'compatible' properly (as a list).
  const dt_property_t* prop = dt_get_prop(dtnode, "compatible");
  if (!prop || kstrcmp(prop->val, "ns16550a") != 0) {
    return -EINVAL;
  }

  u16550_t* uart = (u16550_t*)kmalloc(sizeof(u16550_t));
  if (!uart) {
    return -ENOMEM;
  }

  const size_t kMaxInts = 5;
  dt_interrupt_t interrupts[kMaxInts];
  int result = dtint_extract(tree, dtnode, interrupts, kMaxInts);
  if (result < 0) {
    klogfm(KL_GENERAL, WARNING,
           "Warning: unable to get interrupt information from %s\n", node_path);
    return -EINVAL;
  }

  if (result > 1) {
    klogfm(KL_GENERAL, WARNING,
           "Warning: UART %s has multiple interrupts, ignoring all but the "
           "first\n",
           node_path);
  }
  dt_interrupt_t mapped;
  if (dtint_map(tree, dtnode, &interrupts[0], arch_irq_root(), &mapped)) {
    klogfm(KL_GENERAL, WARNING,
           "Warning: unable to map UART %s interrupt into root controller\n",
           node_path);
    return -EINVAL;
  }
  irq_t irq = dtint_flatten(&mapped);

  // TODO(aoates): make this /dev/ttyS rather than /dev/tty.
  uart->io.type = IO_MEMORY;
  uart->io.base = phys2virt(katou_hex(dt_get_unit(dtnode)));
  uart->interrupt = irq;
  apos_dev_t cdev;
  result = u16550_create_internal(uart, &cdev);
  if (result) {
    return result;
  }

  serial_driver_data_t* serial = KMALLOC(serial_driver_data_t);
  serial->chardev = cdev;
  driver->type = "serial";
  driver->data = serial;
  return 0;
}
