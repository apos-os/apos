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

// Contains basic structs and functions (including initialization) for the USB
// driver.
#ifndef APOO_DEV_USB_USB_H
#define APOO_DEV_USB_USB_H

#include <stdint.h>

#include "dev/usb/descriptor.h"
#include "dev/usb/device.h"
#include "dev/usb/request.h"

#define USB_DEFAULT_ADDRESS 0
#define USB_DEFAULT_CONTROL_PIPE 0
// The configuration value of an unconfigured device.
#define USB_NO_CONFIGURATION 0

// Standard class codes.
#define USB_CLASS_HUB 0x09

struct usb_bus;
struct usb_hcdi;

// Initialize the USB subsystem.
//
// Initializes all buses registered thus far.  All host controllers MUST
// have been discovered and registered (with usb_create_bus) before this is
// called.  For instance, PCI must be fully initialized before USB is
// initialized.
void usb_init(void);

// Returns 1 if usb_init() has been called (and returned).
int usb_is_initialized(void);

// Status of an IRP.
enum usb_irp_status {
  USB_IRP_PENDING = 1,
  USB_IRP_SUCCESS,
  USB_IRP_STALL,
  USB_IRP_DEVICE_ERROR,

  // If this is returned, the IRP's endpoint no longer exists (e.g. because the
  // device was disconnected, or reconfigured).  The driver shouldn't attempt to
  // make any further IRPs on that endpoint (which may not exist).
  USB_IRP_ENDPOINT_GONE,
};
typedef enum usb_irp_status usb_irp_status_t;

// An I/O request for the USBD.  To make a request, fill out this struct and use
// one of the functions below.
struct usb_irp {
  usb_endpoint_t* endpoint;

  void* buffer;
  int buflen;

  // Callback to be invoked when the IRP is completed (with success or
  // failure).  The callback will always be invoked on a dedicated USB thread,
  // and should not block.
  void (*callback)(struct usb_irp*, void*);
  void* cb_arg;

  // Out parameters.
  int outlen;
  usb_irp_status_t status;
};
typedef struct usb_irp usb_irp_t;

// Initialize an IRP.
void usb_init_irp(usb_irp_t* irp);

// Allocate (and free) a usb_dev_request_t that can be used with
// usb_send_request.
usb_dev_request_t* usb_alloc_request(void);
void usb_free_request(usb_dev_request_t* request);

// For all of these, the endpoint, IRP, and request (if given) must live until
// the callback is invoked.

// Send a request on a control pipe.  If the IRP is successfully scheduled,
// returns 0 and the IRP's callback will be invoked (with either success or
// failure).  If there is an error scheduling the IRP, then -errno is returned,
// and the IRP's callback will NOT be invoked.
int usb_send_request(usb_irp_t* irp, usb_dev_request_t* request);

// Receive data on a function-to-host interrupt or bulk endpoint.
int usb_send_data_in(usb_irp_t* irp);

// Send data on a host-to-function endpoint.
int usb_send_data_out(usb_irp_t* irp);

// Cancel any outstanding IRPs on the given endpoint, and make them return
// USB_IRP_ENDPOINT_GONE.
void usb_cancel_endpoint_irp(usb_endpoint_t* endpoint);

// Packet ID types (PIDs).
// TODO(aoates): move this to a usb-internal header (since clients don't need
// it).
enum usb_pid {
  USB_PID_IN = 0x69,
  USB_PID_OUT = 0xE1,
  USB_PID_SETUP = 0x2D,
};
typedef enum usb_pid usb_pid_t;

#endif
