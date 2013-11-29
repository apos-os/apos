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
#include "memory/kmalloc.h"

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

  usb_desc_list_node_t* cnode = list_out;
  int bytes_left_to_read = config->wTotalLength - config->bLength;
  buf += config->bLength;
  while (bytes_left_to_read > 0 && buflen > 0) {
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
    buflen -= desc->bLength;
    bytes_left_to_read -= desc->bLength;
  }

  if (buflen == 0 && bytes_left_to_read > 0) {
    klogf("WARNING: ran out of buffer space reading descriptors, truncating "
          "at %d bytes\n", config->wTotalLength - bytes_left_to_read);
    // TODO(aoates): free all the descriptors and nodes!
    return -ENOMEM;
  }

  return 0;
}

static const char* desc_type(uint8_t type) {
  switch (type) {
    case USB_DESC_DEVICE: return "DEVICE";
    case USB_DESC_CONFIGURATION: return "CONFIGURATION";
    case USB_DESC_STRING: return "STRING";
    case USB_DESC_INTERFACE: return "INTERFACE";
    case USB_DESC_ENDPOINT: return "ENDPOINT";
    case USB_DESC_DEVICE_QUALIFIER: return "DEVICE_QUALIFIER";
    case USB_DESC_OTHER_SPEED_CONFIGURATION: return "OTHER_SPEED_CONFIGURATION";
    case USB_DESC_INTERFACE_POWER: return "INTERFACE_POWER";
    default: return "<unknown>";
  }
}

void usb_print_desc_list(usb_desc_list_node_t* list) {
  int count = 0;
  while (list != 0x0) {
    klogf("Descriptor %d:\n", count);
    usb_print_desc(list->desc);
    list = list->next;
    ++count;
  }
  klogf("<%d total descriptors>\n", count);
}

void usb_print_desc(usb_desc_base_t* desc) {
  switch (desc->bDescriptorType) {
    case USB_DESC_DEVICE:
      usb_print_desc_dev((usb_desc_dev_t*)desc);
      return;
    case USB_DESC_CONFIGURATION:
      usb_print_desc_config((usb_desc_config_t*)desc);
      return;
    case USB_DESC_INTERFACE:
      usb_print_desc_interface((usb_desc_interface_t*)desc);
      return;
    case USB_DESC_ENDPOINT:
      usb_print_desc_endpoint((usb_desc_endpoint_t*)desc);
      return;
    default:
      klogf("  bLength: %d\n", desc->bLength);
      klogf("  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
      klogf("  <%d bytes of data>\n", desc->bLength);
      return;
  }
}

void usb_print_desc_dev(usb_desc_dev_t* dev_desc) {
  klogf("  bLength: %d\n", dev_desc->bLength);
  klogf("  bDescriptorType: %s (%d)\n", desc_type(dev_desc->bDescriptorType),
        dev_desc->bDescriptorType);
  klogf("  bcdUSB: 0x%x\n", dev_desc->bcdUSB);
  klogf("  bDeviceClass: 0x%x\n", dev_desc->bDeviceClass);
  klogf("  bDeviceSubClass: 0x%x\n", dev_desc->bDeviceSubClass);
  klogf("  bDeviceProtocol: 0x%x\n", dev_desc->bDeviceProtocol);
  klogf("  bMaxPacketSize0: %d\n", dev_desc->bMaxPacketSize0);
  klogf("  idVendor: 0x%x\n", dev_desc->idVendor);
  klogf("  idProduct: 0x%x\n", dev_desc->idProduct);
  klogf("  bcdDevice: 0x%x\n", dev_desc->bcdDevice);
  klogf("  iManufacturer: 0x%x\n", dev_desc->iManufacturer);
  klogf("  iProduct: 0x%x\n", dev_desc->iProduct);
  klogf("  iSerialNumber: 0x%x\n", dev_desc->iSerialNumber);
  klogf("  bNumConfigurations: %d\n", dev_desc->bNumConfigurations);
}

void usb_print_desc_config(usb_desc_config_t* desc) {
  klogf("  bLength: %d\n", desc->bLength);
  klogf("  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  klogf("  wTotalLength: %d\n", desc->wTotalLength);
  klogf("  bNumInterfaces: %d\n", desc->bNumInterfaces);
  klogf("  bConfigurationValue: 0x%x\n", desc->bConfigurationValue);
  klogf("  iConfiguration: 0x%x\n", desc->iConfiguration);
  klogf("  bmAttributes: 0x%x\n", desc->bmAttributes);
  klogf("  bMaxPower: %d\n", desc->bMaxPower);
}

void usb_print_desc_interface(usb_desc_interface_t* desc) {
  klogf("  bLength: %d\n", desc->bLength);
  klogf("  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  klogf("  bInterfaceNumber: %d\n", desc->bInterfaceNumber);
  klogf("  bAlternateSetting: %d\n", desc->bAlternateSetting);
  klogf("  bNumEndpoints: %d\n", desc->bNumEndpoints);
  klogf("  bInterfaceClass: 0x%x\n", desc->bInterfaceClass);
  klogf("  bInterfaceSubClass: 0x%x\n", desc->bInterfaceSubClass);
  klogf("  bInterfaceProtocol: 0x%x\n", desc->bInterfaceProtocol);
  klogf("  iInterface: %d\n", desc->iInterface);
}

void usb_print_desc_endpoint(usb_desc_endpoint_t* desc) {
  klogf("  bLength: %d\n", desc->bLength);
  klogf("  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  klogf("  bEndpointAddress: %d (%s)\n", desc->bEndpointAddress & 0x0F,
        desc->bEndpointAddress & USB_DESC_ENDPOINT_DIR_IN ? "IN" : "OUT");
  klogf("  bmAttributes: 0x%x\n", desc->bmAttributes);
  klogf("  wMaxPacketSize: %d\n", desc->wMaxPacketSize);
  klogf("  bInterval: %d\n", desc->bInterval);
}
