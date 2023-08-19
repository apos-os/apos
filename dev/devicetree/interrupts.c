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

static int get_int32_prop(const dt_node_t* node, const char* propname) {
  const dt_property_t* prop = dt_get_prop(node, propname);
  if (!prop) {
    return -EINVAL;
  }
  if (prop->val_len != sizeof(uint32_t)) {
    return -EINVAL;
  }
  uint32_t val = btoh32(*(const uint32_t*)prop->val);
  if (val > 10)  {
    return -EINVAL;  // Sanity check
  }

  return val;
}

static int get_int_cells(const dt_node_t* node) {
  int val = get_int32_prop(node, "#interrupt-cells");
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

#define MAX_NODE_UNIT_LEN 10

int dtint_map(const dt_tree_t* tree, const dt_node_t* node,
              const dt_interrupt_t* intr, const dt_node_t* root,
              dt_interrupt_t* intr_out) {
  // Fast-track the simple case, which might be for an node that doesn't even
  // have a reg/unit address.
  if (intr->int_parent == root) {
    *intr_out = *intr;
    return 0;
  }

  // Rather than track the node obect through the mapping (which requires more
  // lookups), we track only its unit address.
  // TODO(aoates): consider making this a standard shared struct type (like
  // dt_interrupt_t).
  uint32_t node_unit[MAX_NODE_UNIT_LEN];
  int node_unit_len;

  const dt_property_t* node_reg = dt_get_prop(node, "reg");
  // TODO(aoates): is it allowed to have no reg if the child unit is
  // unambiguous?  Can reg be empty?
  node_unit_len = node->context.address_cells;
  if (!node_reg ||
      node_reg->val_len %
              ((node->context.address_cells + node->context.size_cells) *
               sizeof(uint32_t)) !=
          0 ||
      (int)node_reg->val_len < node_unit_len) {
    klogfm(KL_GENERAL, WARNING, "Malformed reg in devicetree\n");
    return -EINVAL;
  }
  const uint32_t* node_reg_vals = (const uint32_t*)node_reg->val;
  for (int i = 0; i < node_unit_len; ++i) {
    node_unit[i] = btoh32(node_reg_vals[i]);
  }

  dt_interrupt_t scratch;
  while (intr->int_parent != root) {
    const dt_property_t* map_prop =
        dt_get_prop(intr->int_parent, "interrupt-map");
    const dt_property_t* map_mask_prop =
        dt_get_prop(intr->int_parent, "interrupt-map-mask");
    if (!map_prop || !map_mask_prop) {
      return -EINVAL;
    }
    int interrupt_cells = get_int_cells(intr->int_parent);
    if (interrupt_cells < 0) {
      return interrupt_cells;
    }
    KASSERT(interrupt_cells == intr->cells);

    const uint32_t* map_elts = (const uint32_t*)map_prop->val;
    int map_elt = 0;
    int elts = map_prop->val_len / sizeof(uint32_t);
    bool match = false;
    while (map_elt < elts) {
      if (elts - map_elt < node_unit_len + interrupt_cells + 1) {
        klogfm(KL_GENERAL, WARNING,
               "Malformed interrupt-map (too short) in devicetree\n");
        return -EINVAL;
      }

      // Compare the masked node unit address and the interrupt specifier to the
      // map entry.
      match = true;
      const uint32_t* mask_vals = (const uint32_t*)map_mask_prop->val;
      for (int i = 0; i < node_unit_len + interrupt_cells; ++i) {
        uint32_t val =
            (i < node_unit_len) ? node_unit[i] : intr->_int[i - node_unit_len];
        val &= btoh32(mask_vals[i]);
        if (val != btoh32(map_elts[map_elt])) {
          match = false;
          // Keep going to keep indexes and loops in line.
        }
        map_elt++;
      }

      // Get the parent phandle.  Even if the interrupt didn't match, we need to
      // look up the parent so we can know how many elements to skip.
      KASSERT_DBG(map_elt < elts);
      uint32_t elt_parent_ph = btoh32(map_elts[map_elt++]);
      const dt_node_t* elt_parent = dt_lookup_phandle(tree, elt_parent_ph);
      if (!elt_parent) {
        klogfm(KL_GENERAL, WARNING,
               "Malformed interrupt-map (bad parent handle) in devicetree\n");
        return -EINVAL;
      }

      int parent_interrupt_cells = get_int_cells(elt_parent);
      if (parent_interrupt_cells < 0) {
        klogfm(KL_GENERAL, WARNING,
               "Malformed interrupt-map (bad parent) in devicetree\n");
        return -EINVAL;
      }

      int parent_address_cells = get_int32_prop(elt_parent, "#address-cells");
      if (parent_address_cells < 0) {
        klogfm(KL_GENERAL, WARNING,
               "Malformed interrupt-map (missing #address-cells in parent) in "
               "devicetree\n");
        return -EINVAL;
      }

      // Make sure we have enough elements left.
      if (elts - map_elt < parent_address_cells + parent_interrupt_cells) {
        klogfm(KL_GENERAL, WARNING,
               "Malformed interrupt-map (too short) in devicetree\n");
        return -EINVAL;
      }

      KASSERT(parent_interrupt_cells < DT_INT_MAX_CELLS);
      // We matched an interrupt!
      if (match) {
        scratch.int_parent = elt_parent;
        scratch.cells = parent_interrupt_cells;
        // Get the new node address from the mapping.
        node_unit_len = parent_address_cells;
        for (int i = 0; i < parent_address_cells; ++i) {
          node_unit[i] = btoh32(map_elts[map_elt + i]);
        }
        map_elt += parent_address_cells;
        for (int i = 0; i < parent_interrupt_cells; ++i) {
          scratch._int[i] = btoh32(map_elts[map_elt + i]);
        }
        intr = &scratch;
        break;
      }

      // Not matched, go to the next interrupt.
      map_elt += parent_address_cells + parent_interrupt_cells;
    }

    // If we didn't find anything matching the map, we're done.
    if (!match) {
      return -ENOENT;
    }
  }
  *intr_out = *intr;
  return 0;
}
