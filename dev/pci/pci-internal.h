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

#ifndef APOO_DEV_PCI_PCI_INTERNAL_H
#define APOO_DEV_PCI_PCI_INTERNAL_H

#include "dev/pci/pci-driver.h"

#define PCI_STATUS_REG_OFFSET 0x04

#define PCI_BUS_MIN 0x00
#define PCI_BUS_MAX 0xFF
#define PCI_DEVICE_MIN 0x00
#define PCI_DEVICE_MAX 0x1F
#define PCI_DEVICES_PER_BUS (PCI_DEVICE_MAX + 1)
#define PCI_FUNCTION_MIN 0x00
#define PCI_FUNCTION_MAX 0x07
#define PCI_FUNCTIONS_PER_DEVICE (PCI_FUNCTION_MAX + 1)
#define PCI_REGISTER_MIN 0x00
#define PCI_REGISTER_MAX 0xFC

#define PCI_HEADER_IS_MULTIFUNCTION 0x80

void pci_add_device(pci_device_t* pcidev);

uint32_t pcie_read_config(pci_device_t* pcidev, uint8_t reg_offset);
void pcie_write_config(pci_device_t* pcidev, uint8_t reg_offset,
                       uint32_t value);

// Parses the given "raw" BAR values, which must be set in the bar structs.
// Updates the parsed bars with the address portion (IO port or memory address)
// in the io.base field.  Note that,
// a) the address is a PCI-visible address (depending on the architecture, may
//    not be mapped to the CPU's memory view or virtual address).
// b) if a 64-bit BAR on a 32-bit system and the value is out-of-range, parsing
//    will fail with ERANGE.
// c) similar to (a), an ioport BAR will be with devio type IO_PORT, even if the
//    host does not support ioport --- the caller must translate both type and
//    address.
//
// A zero BAR will be marked as valid, since it may be depending on the
// architecture.  The caller must check for these.
int pci_parse_bars(pci_device_t* dev);

#endif
