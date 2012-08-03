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

#ifndef APOO_DEV_USB_REQUEST_H
#define APOO_DEV_USB_REQUEST_H

#include <stdint.h>

// Device request.  See section 9.3 of the USB 2.0 spec.
struct usb_dev_request {
  uint8_t bmRequestType;
  uint8_t bRequest;
  uint16_t wValue;
  uint16_t wIndex;
  uint16_t wLength;
};
typedef struct usb_dev_request usb_dev_request_t;

// Flags in the bmRequestType field.
#define USB_DEVREQ_HOST2DEV    0x00
#define USB_DEVREQ_DEV2HOST    0x80

#define USB_DEVREQ_TYPE_MASK   0x60
#define USB_DEVREQ_TYPE_OFFSET 5
#define USB_DEVREQ_TYPE_STD    0
#define USB_DEVREQ_TYPE_CLASS  1
#define USB_DEVREQ_TYPE_VENDOR 2

#define USB_DEVREQ_RCPT_MASK   0x1F
#define USB_DEVREQ_RCPT_DEV    0
#define USB_DEVREQ_RCPT_IFACE  1
#define USB_DEVREQ_RCPT_ENDPT  2
#define USB_DEVREQ_RCPT_OTHER  3

// Standard USB requests (values of the bRequest field).
#define USB_DEVREQ_GET_STATUS         0
#define USB_DEVREQ_CLEAR_FEATURE      1
#define USB_DEVREQ_SET_FEATURE        3
#define USB_DEVREQ_SET_ADDRESS        5
#define USB_DEVREQ_GET_DESCRIPTOR     6
#define USB_DEVREQ_SET_DESCRIPTOR     7
#define USB_DEVREQ_GET_CONFIGURATION  8
#define USB_DEVREQ_SET_CONFIGURATION  9
#define USB_DEVREQ_GET_INTERFACE     10
#define USB_DEVREQ_SET_INTERFACE     11
#define USB_DEVREQ_SYNCH_FRAME       12

// Descriptor types (for GET/SET_DESCRIPTOR requests).
// TODO(aoates): unify abbreviation (DEV vs DEVICE, etc) use across entire USB
// subsystem.
#define USB_DESC_DEV                  1
#define USB_DESC_CONFIG               2
#define USB_DESC_STRING               3
#define USB_DESC_IFACE                4
#define USB_DESC_ENDPT                5
#define USB_DESC_DEV_QUAL             6
#define USB_DESC_OTHER_SPEED_CONFIG   7
#define USB_DESC_IFACE_POWER          8

#endif
