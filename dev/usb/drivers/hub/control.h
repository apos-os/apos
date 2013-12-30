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

// Functions to control a hub through it's standard endpoints.  These are used
// by the hub driver's state machine to configure and control each hub.
#ifndef APOO_DEV_USB_DRIVERS_HUB_CONTROL_H
#define APOO_DEV_USB_DRIVERS_HUB_CONTROL_H

#include "dev/usb/device.h"
#include "dev/usb/drivers/hub/hub.h"
#include "dev/usb/usb.h"

// Read the hub's hub descriptor and invoke the given callback.
void usb_hubd_get_hub_descriptor(
    usb_device_t* dev, usb_hubd_desc_t* desc,
    void (*callback)(usb_device_t*, int /* success or -error */));

#endif
