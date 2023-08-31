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

#ifndef APOO_DEV_PCI_PCI_LEGACY_H
#define APOO_DEV_PCI_PCI_LEGACY_H

#include <stdint.h>

void pci_legacy_init(void);
uint32_t pci_legacy_read_config(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t reg_offset);
void pci_legacy_write_config(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t reg_offset, uint32_t value);

#endif
