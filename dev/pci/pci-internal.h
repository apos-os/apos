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
#define PCI_FUNCTION_MIN 0x00
#define PCI_FUNCTION_MAX 0x07
#define PCI_REGISTER_MIN 0x00
#define PCI_REGISTER_MAX 0xFC

#define PCI_HEADER_IS_MULTIFUNCTION 0x80

void pci_add_device(pci_device_t* pcidev);

#endif
