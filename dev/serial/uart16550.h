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

// An extremely limited driver for a 16550-compatible serial device.
// TODO(aoates): support actual UART settings for use outside qemu.
#ifndef APOO_DEV_SERIAL_UART16550_H
#define APOO_DEV_SERIAL_UART16550_H

#include "dev/dev.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/drivers.h"

// Create a TTY chardev using the legacy PC COM1 IO ports.
int u16550_create_legacy(apos_dev_t* dev);

// Devicetree driver loader.  Stores a serial_driver_data_t in the driver data.
int u16550_driver(const dt_tree_t* tree, const dt_node_t* node,
                  const char* node_path, dt_driver_info_t* driver);

#endif
