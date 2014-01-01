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

#include "dev/usb/device.h"

usb_ttype_t usb_desc_endpoint_type(const usb_desc_endpoint_t* endpoint) {
  switch (endpoint->bmAttributes & USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_MASK) {
    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_CONTROL:
      return USB_CONTROL;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_ISO:
      return USB_ISOCHRONOUS;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_BULK:
      return USB_BULK;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_INTERRUPT:
      return USB_INTERRUPT;

    default:
      return USB_INVALID_TTYPE;
  }
}

usb_dir_t usb_desc_endpoint_dir(const usb_desc_endpoint_t* endpoint) {
  if ((endpoint->bmAttributes & USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_MASK) ==
      USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_CONTROL) {
    return USB_INVALID_DIR;
  } else {
    return (endpoint->bEndpointAddress & USB_DESC_ENDPOINT_DIR_IN) ?
        USB_IN : USB_OUT;
  }
}
