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

#include "dev/usb/drivers/hub.h"

#include "common/kassert.h"
#include "common/klog.h"

int usb_hubd_check_device(usb_device_t* dev) {
  KASSERT_DBG(dev->state == USB_DEV_ADDRESS);
  KASSERT_DBG(dev->dev_desc.bDescriptorType = USB_DESC_DEVICE);

  if (dev->dev_desc.bDeviceClass == USB_HUBD_HUB_CLASSCODE &&
      dev->dev_desc.bDeviceSubClass == 0 &&
      dev->dev_desc.bDeviceProtocol == 0) {
    if (dev->dev_desc.bLength != 0x12 ||
        dev->dev_desc.bMaxPacketSize0 != 64 ||
        dev->dev_desc.bNumConfigurations != 1 ||
        dev->speed != USB_FULL_SPEED) {
      klogf("Warning: invalid USB hub device descriptor; ignoring\n");
      return 0;
    }

    return 1;
  }

  return 0;
}

int usb_hubd_adopt_device(usb_device_t* dev) {
  klogf("USB: found hub device\n");
  return 0;
}
