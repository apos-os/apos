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
#include "dev/devicetree/interrupts.h"

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "dev/devicetree/devicetree.h"

irq_t dtint_flatten(const dt_interrupt_t* intr) {
  KASSERT_MSG(intr->cells == 1,
              "Only single-cell interrupts currently supported");
  return intr->_int[0];
}

static int get_int_cells(const dt_node_t* node) {
  const dt_property_t* cells_prop = dt_get_prop(node, "#interrupt-cells");
  if (!cells_prop) {
    return -EINVAL;
  }
  if (cells_prop->val_len != sizeof(uint32_t)) {
    return -EINVAL;
  }
  uint32_t val = btoh32(*(const uint32_t*)cells_prop->val);
  if (val == 0 || val > DT_INT_MAX_CELLS)  {
    return -EINVAL;  // Sanity check
  }

  return val;
}

int dtint_extract(const dt_tree_t* tree, const dt_node_t* node,
                  dt_interrupt_t* out_array, size_t max_ints) {
  // TODO(aoates): check interrupts-extended.

  // Find interrupt parent.
  const dt_node_t* intparent =
      dt_lookup_prop_phandle(tree, node, "interrupt-parent");
  if (!intparent) intparent = node->parent;
  if (!intparent) {
    return -EINVAL;
  }

  // The parent should have #interrupt-cells, whether a controller or a nexus.
  int int_cells = get_int_cells(intparent);
  if (int_cells < 0) {
    return int_cells;
  }

  // Finally get the interrupts array.
  const dt_property_t* ints_prop = dt_get_prop(node, "interrupts");
  if (!ints_prop) {
    return -EINVAL;
  }

  if (ints_prop->val_len % (sizeof(uint32_t) * int_cells) != 0) {
    return -EINVAL;
  }

  size_t num_ints = ints_prop->val_len / (sizeof(uint32_t) * int_cells);
  if (num_ints > max_ints) {
    return -ENOMEM;
  }

  const uint32_t* cells = (const uint32_t*)ints_prop->val;
  for (size_t i = 0; i < num_ints; ++i) {
    out_array[i].cells = int_cells;
    out_array[i].int_parent = intparent;
    for (size_t cell = 0; cell < DT_INT_MAX_CELLS; ++cell) {
      if (cell < (size_t)int_cells) {
        size_t idx = i * int_cells + cell;
        out_array[i]._int[cell] = btoh32(cells[idx]);
      } else {
        out_array[i]._int[cell] = 0;
      }
    }
  }

  return num_ints;
}

int dtint_map(const dt_tree_t* tree, const dt_node_t* node,
              const dt_interrupt_t* intr, const dt_node_t* root,
              dt_interrupt_t* intr_out) {
  // Without support for nexus and maps, this is very simple.
  if (intr->int_parent != root) {
    return -EINVAL;
  }
  *intr_out = *intr;
  return 0;
}
