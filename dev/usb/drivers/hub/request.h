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

// Hub-specific requests and helpers for making them.
#ifndef APOO_DEV_USB_DRIVERS_HUB_REQUEST_H
#define APOO_DEV_USB_DRIVERS_HUB_REQUEST_H

#include "dev/usb/request.h"

void usb_make_GET_HUB_DESCRIPTOR(usb_dev_request_t* req_out, uint16_t length);
void usb_make_GET_PORT_STATUS(usb_dev_request_t* req_out, int port);
void usb_make_CLEAR_PORT_FEATURE(usb_dev_request_t* req_out, int port, int feature);
void usb_make_SET_PORT_FEATURE(usb_dev_request_t* req_out, int port, int feature);

#endif
