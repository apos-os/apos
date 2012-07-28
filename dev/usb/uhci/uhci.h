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

#ifndef APOO_DEV_USB_UHCI_H
#define APOO_DEV_USB_UHCI_H

#include <stdint.h>

#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"

// Data for a single UHCI USB controller.
struct usb_uhci {
  uint32_t base_port;  // USBBASE register.
};
typedef struct usb_uhci usb_uhci_t;

// Register a UHCI controller with the given base port offset.
void usb_uhci_register_controller(usb_uhci_t c);

// Returns the number of detecte UHCI controllers.
int usb_uhci_num_controllers();

// Returns one of the UHCI controllers.
usb_uhci_t* usb_uhci_get_controller(int i);

#endif
