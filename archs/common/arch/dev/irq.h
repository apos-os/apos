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

#ifndef APOO_ARCHS_COMMON_ARCH_DEV_IRQ_H
#define APOO_ARCHS_COMMON_ARCH_DEV_IRQ_H

#include "dev/devicetree/devicetree.h"

typedef int irq_t;

// TODO(aoates): move these to arch-specific location.
#define IRQ0  0
#define IRQ1  1
#define IRQ2  2
#define IRQ3  3
#define IRQ4  4
#define IRQ5  5
#define IRQ6  6
#define IRQ7  7
#define IRQ8  8
#define IRQ9  9
#define IRQ10 10
#define IRQ11 11
#define IRQ12 12
#define IRQ13 13
#define IRQ14 14
#define IRQ15 15

// Initialize the platform's interrupt controller(s).
void arch_irq_init(void);

// Register a handler to be called when a particular IRQ fires.
typedef void (*irq_handler_t)(void*);
void register_irq_handler(irq_t irq, irq_handler_t handler, void* arg);

// On architectures supporting devicetree, returns the devicetree node
// corresponding to the interrupt root (i.e, the controller that
// register_irq_handler() registers a handler on).
const dt_node_t* arch_irq_root(void);

#endif
