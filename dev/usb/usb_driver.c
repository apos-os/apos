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

#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/usb/bus.h"
#include "dev/usb/device.h"
#include "dev/usb/usb_driver.h"
#include "kmalloc.h"

void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint) {
  KASSERT(endpoint->endpoint_idx < USB_NUM_ENDPOINTS);
  KASSERT(dev->endpoints[endpoint->endpoint_idx] == 0x0);
  KASSERT(endpoint->device == 0x0);

  endpoint->device = dev;
  dev->endpoints[endpoint->endpoint_idx] = endpoint;

  endpoint->hcd_data = 0x0;
  if (dev->bus->hcd->register_endpoint != 0x0) {
    dev->bus->hcd->register_endpoint(dev->bus->hcd, endpoint);
  }
}
