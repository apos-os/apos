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

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/usb/uhci/uhci.h"

void usb_uhci_pci_init(pci_device_t* pcidev) {
  uint32_t legsup = pci_read_register(pcidev, 0xC0);
  klogf("Disabling USB legacy support...");
  // Put the controller in the default mode.
  legsup = (legsup & 0xFFFF0000) | 0x2F00;
  pci_write_register(pcidev, 0xC0, legsup);

  const pci_bar_t* bar = &pcidev->bar[4];
  usb_uhci_register_controller(bar->io, pcidev->host_irq);
}
