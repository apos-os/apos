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

#ifndef APOO_DEV_DEVICETREE_DRIVERS_H
#define APOO_DEV_DEVICETREE_DRIVERS_H

#include "dev/devicetree/devicetree.h"

typedef struct {
  const char* name;  // Driver name.
  const char* type;  // Generic type name that indicates the type of `data`.
  const dt_node_t* node;  // Associated node.
  void* data;
} dt_driver_info_t;

// Given a devicetree, comb it for devices with registered compatible drivers
// and instantiate them.
void dtree_load_drivers(const dt_tree_t* tree);

// Return the driver loaded for the given dt_node_t, or NULL if none has been.
dt_driver_info_t* dtree_get_driver(const dt_node_t* node);

#endif
