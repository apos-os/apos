// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

// Driver for the APOS qemu profiler.
#ifndef APOO_DEV_QEMU_PROFILER_H
#define APOO_DEV_QEMU_PROFILER_H

#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/drivers.h"

// Driver loader.
int qemu_profiler_driver(const dt_tree_t* tree, const dt_node_t* node,
                         const char* node_path, dt_driver_info_t* driver);

// Enable profiling.
int qemu_profiler_enable(void);

// Disable profiling.
int qemu_profiler_disable(void);

#endif
