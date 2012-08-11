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

// Fake hub device implementation for the UHCI root hub provided by the
// controller.
#ifndef APOO_DEV_USB_UHCI_UHCI_HUB_H
#define APOO_DEV_USB_UHCI_UHCI_HUB_H

#include "dev/usb/request.h"
#include "dev/usb/uhci/uhci.h"

// All the data needed for faking a hub.
struct uhci_hub {
  usb_uhci_t* hc;  // The associated controller.

  // TODO(aoates): we'll probably have a global state enum at some point; use
  // that instead of this when we do.
  enum {
    DEFAULT,
    ADDRESS,
    CONFIGURED,
  } state;

  // The state of the current IRP on the default control pipe.  We're pretty
  // brittle in what we expect to get from the USBD.
  enum {
    IRP_SETUP,  // Waiting for a SETUP.
    IRP_DATA,  // Waiting for an IN/OUT data packet.
    IRP_STATUS,  // Waiting for a STATUS packet (IN/OUT).
  } dcp_irp_state;

  // A copy of the request being handled on the default control pipe, if the irp
  // state is IRP_DATA or IRP_STATUS.
  usb_dev_request_t dcp_request;

  // The C_PORT_SUSPEND flag for each port.  Set when the resuming the port,
  // when the hub has finished resuming.
  int c_port_suspend[2];

  // The C_PORT_RESET flag for each port.  Set when the reset process for the
  // port is finished.
  int c_port_reset[2];

  // TODO(aoates): support power status for ports (even though it doesn't do
  // anything) --- it's required by the spec.

  // The hub's USB address.
  uint8_t address;
};
typedef struct uhci_hub uhci_hub_t;

// Initialize the driver for the root hub attached to the given controller.
int uhci_hub_init(usb_uhci_t* hc);

// Handle an IRP being sent to the root hub's address.  Returns 0 on success, or
// USB errors.  Returns -errno if there's an out-of-band error (such as no
// memory).
int uhci_hub_handle_irp(uhci_hub_t* hub, usb_hcdi_irp_t* irp);

#endif
