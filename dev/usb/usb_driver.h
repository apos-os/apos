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

#include "dev/usb/device.h"

// Add an endpoint to a device, and register it with the HCD.
void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint);

#endif
