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

// Limited interrupt tracer.  Only supports simple interrupt trees currently.
// The drivers for a device and interrupt controller need to interpret the
// interrupt-specifiers, but this code can trace through the interrupt tree
// without understanding them.
#ifndef APOO_DEV_DEVICETREE_INTERRUPTS_H
#define APOO_DEV_DEVICETREE_INTERRUPTS_H

#include "arch/dev/irq.h"
#include "dev/devicetree/devicetree.h"

#define DT_INT_MAX_CELLS 3
// Opaque interrupt specifier --- code should not access this direcly.
typedef struct {
  uint32_t _int[DT_INT_MAX_CELLS];
  uint8_t cells;
  const dt_node_t* int_parent;
} dt_interrupt_t;

// Given a devicetree interrupt, flatten it into a platform interrupt.
irq_t dtint_flatten(const dt_interrupt_t* intr);

// Given a node, extract its interrupts.  Returns the number of interrupts or
// -errno.
int dtint_extract(const dt_tree_t* tree, const dt_node_t* node,
                  dt_interrupt_t* out_array, size_t max_ints);

// Given a node and an interrupt specifier (which must be an interrupt generated
// by that node), trace up the interrupt tree to the given root and return the
// interrupt mapped into the root's domain.  If we cannot reach the root, fails.
// Returns 0 or -error.
int dtint_map(const dt_tree_t* tree, const dt_node_t* node,
              const dt_interrupt_t* intr, const dt_node_t* root,
              dt_interrupt_t* intr_out);

#endif
