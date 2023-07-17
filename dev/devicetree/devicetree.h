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

#ifndef APOO_DEV_DEVICETREE_DEVICETREE_H
#define APOO_DEV_DEVICETREE_DEVICETREE_H

#include "common/types.h"
#include "dev/devicetree/dtb.h"

// TODO(aoates): eliminate the linked list pointer for properties (unlike nodes,
// which can recurse, properties are flat and should be much easier to build an
// array for).
typedef struct dt_property {
  const char* name;
  size_t val_len;
  const void* val;
  struct dt_property* next;
} dt_property_t;
typedef struct dt_property dt_property_t;

// A parsed devicetree node.
typedef struct dt_node {
  const char* name;
  dt_property_t* properties;
  struct dt_node* children;
  struct dt_node* next;

  // For convenience, parsed node context.
  // TODO(aoates): rather than embed this in each node, point to one copy in the
  // parent.
  dtfdt_node_context_t context;
} dt_node_t;

// A parsed devicetree.
typedef struct dt_tree {
  dt_node_t* root;     // The root node.
  const void* buffer;  // The original buffer.
} dt_tree_t;

// Parse a raw DTB into a dt_parsed_t.  No dynamic allocation is done --- all
// nodes created are allocated from the given buffer.  All strings and data are
// copied into the buffer as well.
dtfdt_parse_result_t dt_create(const void* fdt, dt_tree_t** tree, void* buf,
                               size_t buflen);

// Find a node with the given path.  The final name must match fully (i.e.
// include the @..., if present, even if unambiguous).
const dt_node_t* dt_lookup(const dt_tree_t* tree, const char* path);

// Get the property from the node, or NULL.
const dt_property_t* dt_get_prop(const dt_node_t* node, const char* prop_name);

#endif
