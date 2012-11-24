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
#include "common/kstring.h"
#include "dev/usb/bus.h"
#include "dev/usb/device.h"
#include "dev/usb/usb_driver.h"
#include "kmalloc.h"

void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint) {
  KASSERT(endpoint->endpoint_idx < USB_NUM_ENDPOINTS);
  KASSERT(dev->endpoints[endpoint->endpoint_idx] == 0x0);
  KASSERT(endpoint->device == 0x0);

  endpoint->device = dev;
  dev->endpoints[endpoint->endpoint_idx] = endpoint;

  endpoint->hcd_data = 0x0;
  if (dev->bus->hcd->register_endpoint != 0x0) {
    dev->bus->hcd->register_endpoint(dev->bus->hcd, endpoint);
  }
}

// Create a default control pipe endpoint for the given device.
static void usb_create_default_control_pipe(usb_device_t* dev) {
  usb_endpoint_t* defctrl = (usb_endpoint_t*)kmalloc(sizeof(usb_endpoint_t));
  kmemset(defctrl, 0, sizeof(usb_endpoint_t));

  defctrl->endpoint_idx = USB_DEFAULT_CONTROL_PIPE;
  defctrl->type = USB_CONTROL;
  defctrl->dir = USB_INVALID_DIR;
  defctrl->max_packet = USB_DEFAULT_MAX_PACKET;

  usb_add_endpoint(dev, defctrl);
}

usb_device_t* usb_create_device(usb_bus_t* bus, usb_device_t* parent,
                                usb_speed_t speed) {
  KASSERT(bus->default_address_in_use == 0);

  usb_device_t* dev = (usb_device_t*)kmalloc(sizeof(usb_device_t));
  kmemset(dev, 0, sizeof(usb_device_t));

  dev->bus = bus;
  dev->state = USB_DEV_INVALID;
  dev->address = USB_DEFAULT_ADDRESS;
  dev->speed = speed;

  dev->parent = parent;
  dev->first_child = 0x0;
  dev->next = 0x0;

  if (parent == 0x0) {
    // This is the root hub.
    KASSERT(bus->root_hub == 0x0);
    bus->root_hub = dev;
  } else {
    // Insert at the start of the parent's child list.
    KASSERT(bus->root_hub != 0x0);
    dev->next = parent->first_child;
    parent->first_child = dev;
  }

  // Set up the default control endpoint.
  usb_create_default_control_pipe(dev);

  bus->default_address_in_use = 1;
  return dev;
}
