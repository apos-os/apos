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

// Interface for host controller drivers (HCDs).
#ifndef APOO_DEV_USB_HCDI_H
#define APOO_DEV_USB_HCDI_H

#include "dev/usb/usb.h"

// A transfer request.
struct usb_hcdi_irp {
  usb_endpoint_t* endpoint;

  // Buffer for input or output, depending on the endpoint type.
  void* buffer;
  uint32_t buflen;

  // Callback to invoke when the IRP is finished (either successfully or on
  // error).
  void (*callback)(struct usb_hcdi_irp* irp);

  // TODO(aoates): packet type, status.
};
typedef struct usb_hcdi_irp usb_hcdi_irp_t;

// Host controller driver interface.  Each host controller driver (e.g UHCI,
// OHCI, EHCI, etc) must implement this interface.
struct usb_hcdi {
  // Register a newly-discovered endpoint with the HCD.  It can store any extra
  // data in the hcd_data field of the endpoint.
  //
  // Optional.
  int (*register_endpoint)(usb_endpoint_t* ep);

  // Unregister the endpoint (for instance, because the device was
  // disconnected), freeing any HCD-specific memory associated with it (in the
  // hcd_data field).
  //
  // Optional.
  int (*unregister_endpoint)(usb_endpoint_t* ep);

  // Schedules the given IRP on the bus.  Returns 0 on success, or -errno on
  // error.  If 0 is returned, then the IRP's callback will eventually be
  // invoked.  If unable to schedule the IRP, then the callback will NOT be
  // invoked.
  int (*schedule_irp)(usb_hcdi_irp_t* irp);

  // HCD-specific data.
  void* dev_data;
};
typedef struct usb_hcdi usb_hcdi_t;

// Registers a host controller with the USBD.  Called from the corresponding HCD
// when it detects the controller.
void usb_register_host_controller(usb_hcdi_t hc);

#endif
