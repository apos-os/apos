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

#ifndef APOO_DEV_USB_BUS_H
#define APOO_DEV_USB_BUS_H

#include "dev/usb/hcd.h"
#include "dev/usb/usb.h"

// A single logical USB bus, corresponding to a single hub controller.
struct usb_bus {
  // The index of this bus.
  int bus_index;

  // The HCD controlling this hub.
  usb_hcdi_t* hcd;

  // The root device, which must be the HCD's root hub.
  usb_device_t* root_hub;

  // The next free address.
  // TODO: allocate and free addresses so we can't run out.
  uint8_t next_address;

  // Set if there is currently a device on the bus responding to the default
  // address.
  uint8_t default_address_in_use;
};
typedef struct usb_bus usb_bus_t;

// Create and register a new bus with the USBD, associated with the given HC.
// Must be called before usb_init().  Takes ownership of the usb_hcdi_t.
void usb_create_bus(usb_hcdi_t* hc);

// Return the number of buses.
int usb_num_buses(void);

// Return the given bus.
usb_bus_t* usb_get_bus(int i);

#endif
