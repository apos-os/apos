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
#include "dev/usb/request.h"

void usb_make_SET_ADDRESS(usb_dev_request_t* req_out, uint8_t address) {
  req_out->bmRequestType =
      USB_DEVREQ_DIR_HOST2DEV |
      USB_DEVREQ_TYPE_STD |
      USB_DEVREQ_RCPT_DEV;
  KASSERT_DBG(req_out->bmRequestType == 0x0);
  req_out->bRequest = USB_DEVREQ_SET_ADDRESS;
  req_out->wValue = address;
  req_out->wIndex = req_out->wLength = 0;
}

void usb_make_GET_DESCRIPTOR(usb_dev_request_t* req_out,
                             uint8_t type, uint8_t index, uint16_t length) {
  req_out->bmRequestType =
      USB_DEVREQ_DIR_DEV2HOST |
      USB_DEVREQ_TYPE_STD |
      USB_DEVREQ_RCPT_DEV;
  req_out->bRequest = USB_DEVREQ_GET_DESCRIPTOR;
  // Descriptor type in high byte, index in low byte.
  req_out->wValue = (type << 8) | index;
  req_out->wIndex = 0;
  req_out->wLength = length;
}
