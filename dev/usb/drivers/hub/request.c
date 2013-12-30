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

#include "dev/usb/drivers/hub/request.h"

#include "common/kassert.h"
#include "dev/usb/drivers/hub/hub.h"

void usb_make_GET_HUB_DESCRIPTOR(usb_dev_request_t* req_out, uint16_t length)  {
  req_out->bmRequestType =
      USB_DEVREQ_DIR_DEV2HOST |
      USB_DEVREQ_TYPE_CLASS |
      USB_DEVREQ_RCPT_DEV;
  KASSERT_DBG(req_out->bmRequestType == 0xa0);
  req_out->bRequest = USB_DEVREQ_GET_DESCRIPTOR;
  // Descriptor type in high byte, index in low byte.
  req_out->wValue = (USB_HUBD_DESC_TYPE << 8);
  req_out->wIndex = 0;
  req_out->wLength = length;
}

void usb_make_GET_PORT_STATUS(usb_dev_request_t* req_out, int port) {
  req_out->bmRequestType =
      USB_DEVREQ_DIR_DEV2HOST |
      USB_DEVREQ_TYPE_CLASS |
      USB_DEVREQ_RCPT_OTHER;
  KASSERT_DBG(req_out->bmRequestType == 0xa3);
  req_out->bRequest = USB_DEVREQ_GET_STATUS;
  req_out->wValue = 0;
  req_out->wIndex = port;
  req_out->wLength = 4;
}

void usb_make_CLEAR_PORT_FEATURE(usb_dev_request_t* req_out, int port, int feature) {
  req_out->bmRequestType =
      USB_DEVREQ_DIR_HOST2DEV |
      USB_DEVREQ_TYPE_CLASS |
      USB_DEVREQ_RCPT_OTHER;
  KASSERT_DBG(req_out->bmRequestType == 0x23);
  req_out->bRequest = USB_DEVREQ_CLEAR_FEATURE;
  req_out->wValue = feature;
  req_out->wIndex = 0xFF & port;  // TODO(aoates): support indicator selector too.
  req_out->wLength = 0;
}
