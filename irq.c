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

#include "common/io.h"w
#include "common/kassert.h"w
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"

#include "irq.h"

#define PIC_MASTER_CMD  0x20
#define PIC_MASTER_DATA 0x21
#define PIC_SLAVE_CMD   0xA0
#define PIC_SLAVE_DATA  0xA1

#define PIC_EOI         0x20

#define NUM_HANDLERS 16
static irq_handler_t g_handlers[NUM_HANDLERS];

void pic_init() {
  for (int i = 0; i < NUM_HANDLERS; ++i) {
    g_handlers[i] = 0x0;
  }

  outb(PIC_MASTER_CMD, 0x11);
  outb(PIC_SLAVE_CMD, 0x11);
  outb(PIC_MASTER_DATA, 0x20);
  outb(PIC_SLAVE_DATA, 0x28);
  outb(PIC_MASTER_DATA, 0x04);
  outb(PIC_SLAVE_DATA, 0x02);
  outb(PIC_MASTER_DATA, 0x01);
  outb(PIC_SLAVE_DATA, 0x01);
  outb(PIC_MASTER_DATA, 0x0);
  outb(PIC_SLAVE_DATA, 0x0);

  // Inintialize the timer.
  outb(0x43, 0x36);
  uint16_t divisor = 1193180 / 20;
  uint8_t low = (uint8_t)(divisor & 0xFF);
  uint8_t high = (uint8_t)((divisor >> 8) & 0xFF);
  outb(0x40, low);
  outb(0x40, high);
}

void register_irq_handler(uint8_t irq, irq_handler_t handler) {
  // TODO(aoates): probs need to disable interrupts here.
  g_handlers[irq] = handler;
}

void timer_interrupt() {
  klog("tick\n");
}

void irq_handler(uint32_t irq, uint32_t interrupt) {
  if (irq > 7) {
    outb(PIC_SLAVE_CMD, PIC_EOI);
  }
  outb(PIC_MASTER_CMD, PIC_EOI);

  if (g_handlers[irq] != 0x0) {
    g_handlers[irq]();
  }
  //klogf("irq: 0x%x\n", irq);
}
