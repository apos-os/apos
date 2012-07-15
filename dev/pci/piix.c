// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/pci/piix.h"

// Index into the PCI base address array for the IDE bus-master base address.
#define PIIX_BUS_MASTER_BASE_ADDR

void pci_piix_driver_init(pci_device_t* pcidev) {
  // Return any device functions that aren't the IDE interface.
  if (pcidev->device_id != 0x7010) {
    return;
  }

  klogf("PCI: initializing driver for PII/PIIX IDE controller\n");
  KASSERT(pcidev->class_code == 0x1);
  KASSERT(pcidev->subclass_code == 0x1);
  KASSERT(pcidev->prog_if == 0x80);
}
