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
#include "arch/dev/irq.h"

#include "archs/common/arch/dev/irq.h"
#include "archs/riscv64/internal/plic.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "dev/io.h"
#include "main/kernel.h"
#include "proc/spinlock.h"

// Up to MAX_HANDLERS_PER_IRQ can be registered to be called per IRQ.
#define MAX_HANDLERS_PER_IRQ 10
struct handler_block {
  irq_handler_t handlers[MAX_HANDLERS_PER_IRQ];
  void* args[MAX_HANDLERS_PER_IRQ];
  int num;
};
typedef struct handler_block handler_block_t;

// The PLIC supports up to 1023 interrupt sources --- don't bother with that
// many, though, for now.
#define PLIC_MAX_SOURCES 64
static handler_block_t g_handlers[PLIC_MAX_SOURCES];
kspinlock_intsafe_t g_handlers_lock = KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;

#define PLIC_MIN_PRIORITY 1
static devio_t g_plic_io;  // Const after creation.

static const dt_node_t* find_plic(void) {
  const dt_tree_t* tree = get_boot_info()->dtree;
  if (!tree) {
    die("Cannot initialize PLIC without a device tree");
  }

  const dt_node_t* soc = dt_lookup(tree, "/soc");
  KASSERT_MSG(soc != NULL, "Unable to find device node /soc");
  const dt_node_t* plic = soc->children;
  while (plic != NULL && kstr_startswith(plic->name, "plic@") == 0) {
    plic = plic->next;
  }
  KASSERT_MSG(plic != NULL, "Unable to find device node /soc/plic@XXX");

  return plic;
}

static uint32_t get_hart_context(void) {
  // TODO(SMP): get the CPU ID from the boot info.
  const int hart_id = 0;
  // Add one to get the supervisor-mode context.
  return hart_id * 2 + 1;
}

void arch_irq_init(void) {
  // Set up global data structures.
  for (int i = 0; i < PLIC_MAX_SOURCES; ++i) {
    for (int j = 0; j < MAX_HANDLERS_PER_IRQ; ++j) {
      g_handlers[i].handlers[j] = 0x0;
      g_handlers[i].args[j] = 0x0;
    }
    g_handlers[i].num = 0;
  }

  // TODO(aoates): find using 'compatible' rather than matching the node name.
  const dt_node_t* plic = find_plic();
  g_plic_io.type = IO_MEMORY;
  g_plic_io.base = phys2virt(katou_hex(dt_get_unit(plic)));

  // Set min priority to 0 for the current hart, enabling interrupts.
  io_write32(g_plic_io, 0x200000 + 0x1000 * get_hart_context(), 0);

  // Enable external interrupts.
  const uint32_t SEI_BIT = 0x200;
  asm volatile("csrs sie, %0" ::"r"(SEI_BIT));
}

void register_irq_handler(irq_t irq, irq_handler_t handler, void* arg) {
  KASSERT(irq < PLIC_MAX_SOURCES);

  kspin_lock_int(&g_handlers_lock);

  // Set the priority and enable bits for this interrupt source (if needed).
  io_write32(g_plic_io, sizeof(uint32_t) * irq, PLIC_MIN_PRIORITY);
  addr_t enable_addr = 0x2000 + 0x80 * get_hart_context() + 4 * (irq / 32);
  uint32_t enable_bit = 1 << (irq % 32);
  uint32_t cval = io_read32(g_plic_io, enable_addr);
  io_write32(g_plic_io, enable_addr, cval | enable_bit);

  // Install handler.
  KASSERT(g_handlers[irq].num < MAX_HANDLERS_PER_IRQ);
  int idx = g_handlers[irq].num++;
  g_handlers[irq].handlers[idx] = handler;
  g_handlers[irq].args[idx] = arg;

  kspin_unlock_int(&g_handlers_lock);
}

void rsv_external_interrupt(void) {
  const addr_t claim_reg = 0x200000 + 0x1000 * get_hart_context() + 4;
  uint32_t irq = io_read32(g_plic_io, claim_reg);
  KASSERT_DBG(irq != 0);  // TODO(smp): remove this assertion.
  while (irq != 0) {
    klogfm(KL_GENERAL, DEBUG3, "PLIC IRQ %u\n", irq);

    for (int i = 0; i < g_handlers[irq].num; ++i) {
      if (g_handlers[irq].handlers[i] == 0x0) {
        break;
      }

      g_handlers[irq].handlers[i](g_handlers[irq].args[i]);
    }

    // Claim the IRQ, then try and get another.
    io_write32(g_plic_io, claim_reg, irq);
    irq = io_read32(g_plic_io, claim_reg);
  }
}

const dt_node_t* arch_irq_root(void) {
  return find_plic();
}
