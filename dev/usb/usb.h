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

#ifndef APOO_DEV_USB_USB_H
#define APOO_DEV_USB_USB_H

#include <stdint.h>

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

// An endpoint on a given device.
struct usb_endpoint {
  // hdci* controller;
  uint8_t address;  // Device address.
  uint8_t endpoint; // Endpoint number (0-15).
  usb_ttype_t type;
  usb_dir_t dir;  // Only if type != USB_CONTROL (which are bidirectional).

  uint32_t period;  // In frames.  Only for interrupt endpoints.
  uint32_t max_packet;  // Max packet size, in bytes.

  // The speed of the associated device.  This should probably be in the device
  // spec, not here.
  usb_speed_t speed;

  // TODO: bandwidth, error handling reqs

  // Space for HCD-specific data.
  void* hcd_data;
};
typedef struct usb_endpoint usb_endpoint_t;

#endif
