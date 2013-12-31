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

// USB device drivers.
#ifndef APOO_DEV_USB_DRIVERS_DRIVERS_H
#define APOO_DEV_USB_DRIVERS_DRIVERS_H

#include "dev/usb/device.h"

// A USB driver.
typedef struct {
  // Returns non-zero if the driver can handle the given device.
  int (*check_device)(usb_device_t*);

  // Adopt the given device, returning -errno on error.  If this is called,
  // check_device will have been previously called with the same device.
  int (*adopt_device)(usb_device_t*);

  // Human-readable name of the driver.
  const char* name;
} usb_driver_t;

// Finds a driver for the given device, or returns NULL if none can be found.
usb_driver_t* usb_find_driver(usb_device_t* device);

#endif
