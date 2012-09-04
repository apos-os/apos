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

#include "dev/usb/descriptor.h"

#define USB_DEFAULT_ADDRESS 0
#define USB_DEFAULT_CONTROL_PIPE 0
// The configuration value of an unconfigured device.
#define USB_NO_CONFIGURATION 0

// Standard class codes.
#define USB_CLASS_HUB 0x09

struct usb_bus;
struct usb_hcdi;

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

// Packet ID types (PIDs).
// TODO(aoates): move this to a usb-internal header (since clients don't need
// it).
enum usb_pid {
  USB_PID_IN = 0x69,
  USB_PID_OUT = 0xE1,
  USB_PID_SETUP = 0x2D,
};
typedef enum usb_pid usb_pid_t;

enum usb_data_toggle {
  USB_DATA0 = 0,
  USB_DATA1 = 1,
};
typedef enum usb_data_toggle usb_data_toggle_t;

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

  // The current data toggle bit of the endpoint (see section 8.6 of the spec).
  usb_data_toggle_t data_toggle;

  // TODO: bandwidth, error handling reqs

  // Space for HCD-specific data.
  void* hcd_data;
};
typedef struct usb_endpoint usb_endpoint_t;

// A single USB device.
struct usb_device {
  // The bus this device is on.
  struct usb_bus* bus;

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

// Status of an IRP.
enum usb_irp_status {
  USB_IRP_PENDING = 1,
  USB_IRP_SUCCESS,
  USB_IRP_STALL,
  USB_IRP_DEVICE_ERROR,
};
typedef enum usb_irp_status usb_irp_status_t;
#endif
