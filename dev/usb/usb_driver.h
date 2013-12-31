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

// TODO(aoates): should the add/remove endpoint functions be public, or private
// to the USBD?  Should anything other than configuration manipulate these?

// Add an endpoint to a device, and register it with the HCD.
void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint);

// Remove an endpoint from a device, and unregister it with the HCD.  Does not
// free the endpoint.
void usb_remove_endpoint(usb_endpoint_t* endpoint);

// Invoke the given callback when the default address is available.  The
// callback is run inline if it is currently available.
//
// Note: the callback MUST call either usb_release_default_address() or
// usb_init_device() (but not both) to release the default address on the bus.
void usb_acquire_default_address(usb_bus_t* bus,
                                 void (*callback)(usb_bus_t* bus, void* arg),
                                 void* arg);

// Release the default address on the bus, which MUST have been acquired with
// usb_acquire_default_address().
void usb_release_default_address(usb_bus_t* bus);

// Create a new device on the given bus, with the given parent (or NULL) if this
// is the root hub).  Sets the address to the default address on the hub and
// creates the default control pipe.
//
// The created device will be in the INVALID state.  The caller should update
// the state as necessary.
//
// REQUIRES: the default address is held.
usb_device_t* usb_create_device(usb_bus_t* bus, usb_device_t* parent,
                                usb_speed_t speed);

// Initialize a device.  This kicks off a process that will (asynchronously),
//   a) assign an address
//   b) read device descriptors
//   c) configure the device
//   d) look for an appropriate driver
//   e) if one is found, hand the device to the driver
//
// After (a) is complete, the default address will be released and a callback
// waiting to acquire it (if any) will be run.
//
// The device must be in the USB_DEV_DEFAULT state.
void usb_init_device(usb_device_t* dev);

// Send a SET_CONFIGURATION request to the given device.  If config is zero, the
// device is deconfigured.
void usb_set_configuration(usb_device_t* dev, uint8_t config,
                           void (*callback)(usb_device_t*, void*),
                           void* arg);

// Descriptor manipulation utilities.

// Return the configuration values (i.e. the numbers given to SET_CONFIGURATION)
// of the given device in |config_values|.  |config_values| must have at least
// |dev->dev_desk->bNumConfigurations| entries.
void usb_get_configuration_values(usb_device_t* dev, uint8_t* config_values);

#endif
