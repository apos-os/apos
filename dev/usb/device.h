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

// A single USB device's data, configuration and endpoints.
#ifndef APOO_DEV_USB_DEVICE_H
#define APOO_DEV_USB_DEVICE_H

#include "dev/usb/descriptor.h"

struct usb_bus;

// States of a USB device.  See section 9.1 of the USB spec.
enum usb_device_state {
  USB_DEV_ATTACHED = 1,
  USB_DEV_POWERED,
  USB_DEV_DEFAULT,
  USB_DEV_ADDRESS,
  USB_DEV_CONFIGURED,
  USB_DEV_SUSPENDED,
};
typedef enum usb_device_state usb_device_state_t;

// A single USB device.
struct usb_device {
  // The bus this device is on.
  struct usb_bus* bus;

  usb_device_state_t state;

  // The device's address.
  uint8_t address;

  // The device descriptor.
  usb_desc_dev_t dev_desc;

  // An array of configurations, dev_desc->bNumConfigurations in length.  Each
  // element is the beginning of a linked list of descriptors for the given
  // configuration.
  usb_desc_list_node_t* configs;

  // The device's parent (which must be a hub), or NULL if the device is the
  // HC's root hub.
  struct usb_device* parent;

  // The first child of the device, if it is a hub.
  struct usb_device* first_child;

  // The next sibling of the device, if the parent is a hub.
  struct usb_device* next;
};
typedef struct usb_device usb_device_t;

// Transfer types.
enum usb_ttype {
  USB_ISOCHRONOUS,
  USB_INTERRUPT,
  USB_CONTROL,
  USB_BULK,
};
typedef enum usb_ttype usb_ttype_t;

enum usb_dir {
  USB_IN,
  USB_OUT,
};
typedef enum usb_dir usb_dir_t;

enum usb_speed {
  USB_LOW_SPEED,
  USB_FULL_SPEED,
};
typedef enum usb_speed usb_speed_t;

enum usb_data_toggle {
  USB_DATA0 = 0,
  USB_DATA1 = 1,
};
typedef enum usb_data_toggle usb_data_toggle_t;

// An endpoint on a given device.
struct usb_endpoint {
  struct usb_device* device;

  uint8_t endpoint; // Endpoint number (0-15).
  usb_ttype_t type;
  usb_dir_t dir;  // Only if type != USB_CONTROL (which are bidirectional).

  uint32_t period;  // In frames.  Only for interrupt endpoints.
  uint32_t max_packet;  // Max packet size, in bytes.

  // The speed of the associated device.  This should probably be in the device
  // spec, not here.
  usb_speed_t speed;

  // The current data toggle bit of the endpoint (see section 8.6 of the spec).
  usb_data_toggle_t data_toggle;

  // TODO: bandwidth, error handling reqs

  // Space for HCD-specific data.
  void* hcd_data;
};
typedef struct usb_endpoint usb_endpoint_t;

#endif
