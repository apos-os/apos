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

// Hub driver.
#ifndef APOO_DEV_USB_HUB_H
#define APOO_DEV_USB_HUB_H

#include "dev/usb/device.h"

#define USB_HUBD_HUB_CLASSCODE 0x09

// Bits in the status returned by GET_HUB_STATUS.
#define USB_HUBD_HUB_LOCAL_POWER   0x0001
#define USB_HUBD_HUB_OVER_CURRENT  0x0002

#define USB_HUBD_C_HUB_LOCAL_POWER   0x0001
#define USB_HUBD_C_HUB_OVER_CURRENT  0x0002

// Bits in the status returned by GET_PORT_STATUS.
#define USB_HUBD_PORT_CONNECTION   0x0001
#define USB_HUBD_PORT_ENABLE       0x0002
#define USB_HUBD_PORT_SUSPEND      0x0004
#define USB_HUBD_PORT_OVER_CURRENT 0x0008
#define USB_HUBD_PORT_RESET        0x0010
#define USB_HUBD_PORT_POWER        0x0100
#define USB_HUBD_PORT_LOW_SPEED    0x0200
#define USB_HUBD_PORT_HIGH_SPEED   0x0400
#define USB_HUBD_PORT_TEST         0x0800
#define USB_HUBD_PORT_INDICATOR    0x1000

#define USB_HUBD_C_PORT_CONNECTION   0x0001
#define USB_HUBD_C_PORT_ENABLE       0x0002
#define USB_HUBD_C_PORT_SUSPEND      0x0004
#define USB_HUBD_C_PORT_OVER_CURRENT 0x0008
#define USB_HUBD_C_PORT_RESET        0x0010

// Port features (see table 11-17 on p421 of the USB 2.0 spec).
#define USB_HUBD_FEAT_PORT_CONNECTION 0
#define USB_HUBD_FEAT_PORT_ENABLE 1
#define USB_HUBD_FEAT_PORT_SUSPEND 2
#define USB_HUBD_FEAT_PORT_OVER_CURRENT 3
#define USB_HUBD_FEAT_PORT_RESET 4
#define USB_HUBD_FEAT_PORT_POWER 8
#define USB_HUBD_FEAT_PORT_LOW_SPEED 9
#define USB_HUBD_FEAT_C_PORT_CONNECTION 16
#define USB_HUBD_FEAT_C_PORT_ENABLE 17
#define USB_HUBD_FEAT_C_PORT_SUSPEND 18
#define USB_HUBD_FEAT_C_PORT_OVER_CURRENT 19
#define USB_HUBD_FEAT_C_PORT_RESET 20
#define USB_HUBD_FEAT_PORT_TEST 21
#define USB_HUBD_FEAT_PORT_INDICATOR 22

// Hub characteristics (in the wHubCharacteristics field in usb_hubd_desc_t).

// Logical power switching mode.
#define USB_HUBD_CHAR_LPSM_MASK 0x03
#define USB_HUBD_CHAR_LPSM_GANGED 0x00
#define USB_HUBD_CHAR_LPSM_INDIVIDUAL 0x01

#define USB_HUBD_CHAR_COMPOUND 0x04

// Over-current protection mode.
#define USB_HUBD_CHAR_OCPM_MASK 0x18
#define USB_HUBD_CHAR_OCPM_GLOBAL 0x00
#define USB_HUBD_CHAR_OCPM_INDIVIDUAL 0x01
#define USB_HUBD_CHAR_OCPM_NONE1 0x10
#define USB_HUBD_CHAR_OCPM_NONE2 0x11

// TODO(aoates): TT mode.

// Set if port indicators are supported.
#define USB_HUBD_CHAR_PORT_INDC 0x80

// Hub descriptor.
#define USB_HUBD_DESC_TYPE 0x29
struct usb_hubd_desc {
  uint8_t bLength;
  uint8_t bDescriptorType;  // Must be USB_HUBD_DESC_TYPE.
  uint8_t bNbrPorts;  // Number of ports.
  uint16_t wHubCharacteristics;
  uint8_t bPwrOn2PwrGood;
  uint8_t bHubContrCurrent;

  // Variable. First is the DeviceRemovable set, then the PortPwrCtrlMask set.
  // Each set has a single bit for each port, rounded up to an even number of
  // bytes (so for a 3-port hub, the total length would be 2 bytes --- one each
  // for DeviceRemovable and PortPwrCtrlMask.  Only the first 3 bits of each
  // would be meaningful).
  uint8_t PortBits[16];
} __attribute__((packed));
typedef struct usb_hubd_desc usb_hubd_desc_t;

// USB device driver interface.

// Returns 1 if the device is a hub that this driver can handle.
int usb_hubd_check_device(usb_device_t* dev);

// Adopt the given hub device, returning -errno on error.
int usb_hubd_adopt_device(usb_device_t* dev);

#endif
