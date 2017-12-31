// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_DEV_NET_RTL8139_H
#define APOO_DEV_NET_RTL8139_H

#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"

// Called by the PCI subsystem when a matching NIC is discovered.
void pci_rtl8139_init(pci_device_t* pcidev);

#endif
