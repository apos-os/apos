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

// Data toggle setting for an IRP.
enum usb_hcdi_dt {
  USB_DATA_TOGGLE_NORMAL = 1,  // Use the current data toggle from the endpoint.
  USB_DATA_TOGGLE_RESET0,  // Reset the endpoint to DATA0 with this IRP.
  USB_DATA_TOGGLE_RESET1,  // Reset the endpoint to DATA1 with this IRP.
};
typedef enum usb_hcdi_dt usb_hcdi_dt_t;

// A transfer request.
struct usb_hcdi_irp {
  usb_endpoint_t* endpoint;

  // Buffer for input or output, depending on the endpoint type.
  //
  // Note: the buffer MUST be in the physically-mapped memory region, so it must
  // be allocated with slab_alloc or page_alloc, not kmalloc.
  // TODO(aoates): should we remove this requirement?
  void* buffer;
  uint32_t buflen;

  // PID for the IRP.  If the IRP is split into multiple packets, the PID will
  // be used for each.  It is the caller's responsibility to ensure this is
  // appropriate.
  usb_pid_t pid;

  // Data toggle for this IRP.  If NORMAL, the endpoint's current data toggle
  // status will be used.  Otherwise, the endpoint will be reset to the given
  // value for the first packet of the IRP.
  //
  // Either way, if the IRP is split into multiple packets, the endpoint's data
  // toggle will be inverted for each packet (and updated in the endpoint
  // struct).
  usb_hcdi_dt_t data_toggle;

  // Status fields set when the IRP is completed.
  usb_irp_status_t status;
  uint32_t out_len;  // Actual number of bytes read or written.

  // Callback to invoke when the IRP is finished (either successfully or on
  // error).  May be called from an interrupt context.
  void (*callback)(struct usb_hcdi_irp* irp, void* arg);
  void* callback_arg;

  // TODO(aoates): packet type, status.
  void* hcd_data;
};
typedef struct usb_hcdi_irp usb_hcdi_irp_t;

// Host controller driver interface.  Each host controller driver (e.g UHCI,
// OHCI, EHCI, etc) must implement this interface.
struct usb_hcdi {
  // Initialize the host controller.  Called once, from usb_init().
  int (*init)(struct usb_hcdi* hc);

  // Register a newly-discovered endpoint with the HCD.  It can store any extra
  // data in the hcd_data field of the endpoint.
  //
  // The endpoint's device may not be inserted into the device hierarchy yet,
  // but will be otherwise fully initialized.
  //
  // Optional.
  int (*register_endpoint)(struct usb_hcdi* hc, usb_endpoint_t* ep);

  // Unregister the endpoint (for instance, because the device was
  // disconnected), freeing any HCD-specific memory associated with it (in the
  // hcd_data field).
  //
  // Optional.
  int (*unregister_endpoint)(struct usb_hcdi* hc, usb_endpoint_t* ep);

  // Schedules the given IRP on the bus.  Returns 0 on success, or -errno on
  // error.  If 0 is returned, then the IRP's callback will eventually be
  // invoked.  If unable to schedule the IRP, then the callback will NOT be
  // invoked.
  //
  // Only one IRP can be active at a time on a given endpoint.
  int (*schedule_irp)(struct usb_hcdi* hc, usb_hcdi_irp_t* irp);

  // HCD-specific data.
  void* dev_data;
};
typedef struct usb_hcdi usb_hcdi_t;

#endif
