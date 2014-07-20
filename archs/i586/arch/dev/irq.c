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

#include "archs/i586/internal/dev/interrupts-x86.h"
#include "archs/common/arch/dev/irq.h"
#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"

#define PIC_MASTER_CMD  0x20
#define PIC_MASTER_DATA 0x21
#define PIC_SLAVE_CMD   0xA0
#define PIC_SLAVE_DATA  0xA1

#define PIC_READ_ISR    0x0B
#define PIC_EOI         0x20

// Up to MAX_HANDLERS_PER_IRQ can be registered to be called per IRQ.
#define MAX_HANDLERS_PER_IRQ 10
struct handler_block {
  irq_handler_t handlers[MAX_HANDLERS_PER_IRQ];
  void* args[MAX_HANDLERS_PER_IRQ];
  int num;
};
typedef struct handler_block handler_block_t;

// These are the user-defined handlers.
#define NUM_HANDLERS 16
static handler_block_t g_handlers[NUM_HANDLERS];

static void irq_handler(uint32_t interrupt, uint32_t error, int is_user);

void pic_init() {
  for (int i = 0; i < NUM_HANDLERS; ++i) {
    for (int j = 0; j < MAX_HANDLERS_PER_IRQ; ++j) {
      g_handlers[i].handlers[j] = 0x0;
      g_handlers[i].args[j] = 0x0;
    }
    g_handlers[i].num = 0;
  }

  register_interrupt_handler(0x20, &irq_handler);
  register_interrupt_handler(0x21, &irq_handler);
  register_interrupt_handler(0x22, &irq_handler);
  register_interrupt_handler(0x23, &irq_handler);
  register_interrupt_handler(0x24, &irq_handler);
  register_interrupt_handler(0x25, &irq_handler);
  register_interrupt_handler(0x26, &irq_handler);
  register_interrupt_handler(0x27, &irq_handler);
  register_interrupt_handler(0x28, &irq_handler);
  register_interrupt_handler(0x29, &irq_handler);
  register_interrupt_handler(0x2A, &irq_handler);
  register_interrupt_handler(0x2B, &irq_handler);
  register_interrupt_handler(0x2C, &irq_handler);
  register_interrupt_handler(0x2D, &irq_handler);
  register_interrupt_handler(0x2E, &irq_handler);
  register_interrupt_handler(0x2F, &irq_handler);

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
}

void register_irq_handler(uint8_t irq, irq_handler_t handler, void* arg) {
  KASSERT(irq < NUM_HANDLERS);
  KASSERT(g_handlers[irq].num < MAX_HANDLERS_PER_IRQ);
  // TODO(aoates): probs need to disable interrupts here.
  int idx = g_handlers[irq].num++;
  g_handlers[irq].handlers[idx] = handler;
  g_handlers[irq].args[idx] = arg;
}

static void irq_handler(uint32_t interrupt, uint32_t error, int is_user) {
  KASSERT(interrupt >= 0x20 + IRQ0);
  KASSERT(interrupt <= 0x20 + IRQ15);
  KASSERT(error == 0);

  const uint32_t irq = interrupt - 0x20;
  // Check for spurious IRQs.
  if (irq == 7) {
    outb(PIC_MASTER_CMD, PIC_READ_ISR);
    uint8_t isr = inb(PIC_MASTER_CMD);
    if (!(isr & (1 << 7))) {
      // Spurious.  Return.
      return;
    }
  } else if (irq == 15) {
    outb(PIC_SLAVE_CMD, PIC_READ_ISR);
    uint8_t isr = inb(PIC_SLAVE_CMD);
    if (!(isr & (1 << 7))) {
      // Spurious.  Send EOI to master, but not slave.
      outb(PIC_MASTER_CMD, PIC_EOI);
      return;
    }
  }

  if (irq > 7) {
    outb(PIC_SLAVE_CMD, PIC_EOI);
  }
  outb(PIC_MASTER_CMD, PIC_EOI);

  //if (irq != 0 && irq != 1) {
  //  klogf("irq: 0x%x\n", irq);
  //}

  for (int i = 0; i < g_handlers[irq].num; ++i) {
    if (g_handlers[irq].handlers[i] != 0x0) {
      g_handlers[irq].handlers[i](g_handlers[irq].args[i]);
    }
  }
}
