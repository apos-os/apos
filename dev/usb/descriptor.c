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

#include "common/errno.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/usb/descriptor.h"
#include "kmalloc.h"

int usb_parse_descriptors(usb_desc_list_node_t* list_out,
                          void* buf, size_t buflen) {
  if (buf == 0x0 || buflen < sizeof(usb_desc_config_t) ||
      list_out->next != 0x0 || list_out->desc != 0x0) {
    return -EINVAL;
  }

  // First read the configuration descriptor.
  usb_desc_config_t* config =
      (usb_desc_config_t*)kmalloc(sizeof(usb_desc_config_t));
  list_out->desc = (usb_desc_base_t*)config;
  kmemcpy(config, buf, sizeof(usb_desc_config_t));

  klogf("INFO: read config descriptor: \n");
  usb_print_desc_config(config);

  usb_desc_list_node_t* cnode = list_out;
  int bytes_left = config->wTotalLength - config->bLength;
  buf += config->bLength;
  while (bytes_left > 0 && buflen > 0) {
    usb_desc_base_t* desc_in_buf = (usb_desc_base_t*)buf;
    // TODO(aoates): check that bLength is valid.
    usb_desc_base_t* desc = (usb_desc_base_t*)kmalloc(desc_in_buf->bLength);
    kmemcpy(desc, desc_in_buf, desc_in_buf->bLength);

    usb_desc_list_node_t* new_node = (usb_desc_list_node_t*)
        kmalloc(sizeof(usb_desc_list_node_t));
    new_node->desc = desc;
    new_node->next = 0x0;
    cnode->next = new_node;
    cnode = new_node;

    buf += desc->bLength;
    bytes_left -= desc->bLength;
  }

  klogf("Read descriptors: \n");
  cnode = list_out;
  while (cnode) {
    klogf("  len: %d  type: %d\n", cnode->desc->bLength,
          cnode->desc->bDescriptorType);
    cnode = cnode->next;
  }

  return 0;
}

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

void usb_print_desc_config(usb_desc_config_t* desc) {
  klogf("  bLength: %d\n", desc->bLength);
  klogf("  bDescriptorType: 0x%x\n", desc->bDescriptorType);
  klogf("  wTotalLength: %d\n", desc->wTotalLength);
  klogf("  bNumInterfaces: %d\n", desc->bNumInterfaces);
  klogf("  bConfigurationValue: 0x%x\n", desc->bConfigurationValue);
  klogf("  iConfiguration: 0x%x\n", desc->iConfiguration);
  klogf("  bmAttributes: 0x%x\n", desc->bmAttributes);
  klogf("  bMaxPower: %d\n", desc->bMaxPower);
}
