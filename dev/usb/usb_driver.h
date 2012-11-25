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

// Functions for use by USB drivers and other subsystems.
#ifndef APOO_DEV_USB_USB_DRIVER_H
#define APOO_DEV_USB_USB_DRIVER_H

#include "dev/usb/bus.h"
#include "dev/usb/device.h"

// Add an endpoint to a device, and register it with the HCD.
void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint);

// Create a new device on the given bus, with the given parent (or NULL) if this
// is the root hub).  Sets the address to the default address on the hub and
// creates the default control pipe.
//
// The created device will be in the INVALID state.  The caller should update
// the state as necessary.
usb_device_t* usb_create_device(usb_bus_t* bus, usb_device_t* parent,
                                usb_speed_t speed);

// Initialize a device.  This kicks off a process that will (asynchronously),
//   a) assign an address
//   b) read device descriptors
//   c) configure the device
//   d) look for an appropriate driver
//   e) if one is found, hand the device to the driver
//
// After (a) is complete, any callbacks waiting on the bus's default address
// list will be woken up.
// TODO(aoates): figure out this mechanism and implement it.
//
// The device must be in the USB_DEV_DEFAULT state.
void usb_init_device(usb_device_t* dev);

#endif
