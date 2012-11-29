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

#include "common/klog.h"
#include "dev/usb/descriptor.h"

void usb_print_desc_dev(usb_desc_dev_t* dev_desc) {
  klogf("  bLength: 0x%x\n", dev_desc->bLength);
  klogf("  bDescriptorType: 0x%x\n", dev_desc->bDescriptorType);
  klogf("  bcdUSB: 0x%x\n", dev_desc->bcdUSB);
  klogf("  bDeviceClass: 0x%x\n", dev_desc->bDeviceClass);
  klogf("  bDeviceSubClass: 0x%x\n", dev_desc->bDeviceSubClass);
  klogf("  bDeviceProtocol: 0x%x\n", dev_desc->bDeviceProtocol);
  klogf("  bMaxPacketSize0: 0x%x\n", dev_desc->bMaxPacketSize0);
  klogf("  idVendor: 0x%x\n", dev_desc->idVendor);
  klogf("  idProduct: 0x%x\n", dev_desc->idProduct);
  klogf("  bcdDevice: 0x%x\n", dev_desc->bcdDevice);
  klogf("  iManufacturer: 0x%x\n", dev_desc->iManufacturer);
  klogf("  iProduct: 0x%x\n", dev_desc->iProduct);
  klogf("  iSerialNumber: 0x%x\n", dev_desc->iSerialNumber);
  klogf("  bNumConfigurations: 0x%x\n", dev_desc->bNumConfigurations);
}
