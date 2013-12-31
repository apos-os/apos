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

#define KLOG(...) klogfm(KL_USB, __VA_ARGS__)

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
    KLOG(WARNING, "WARNING: ran out of buffer space reading descriptors, "
         "truncating at %d bytes\n", config->wTotalLength - bytes_left_to_read);
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

void usb_print_desc_list(klog_level_t level, usb_desc_list_node_t* list) {
  int count = 0;
  while (list != 0x0) {
    KLOG(level, "Descriptor %d:\n", count);
    usb_print_desc(level, list->desc);
    list = list->next;
    ++count;
  }
  KLOG(level, "<%d total descriptors>\n", count);
}

void usb_print_desc(klog_level_t level, usb_desc_base_t* desc) {
  switch (desc->bDescriptorType) {
    case USB_DESC_DEVICE:
      usb_print_desc_dev(level, (usb_desc_dev_t*)desc);
      return;
    case USB_DESC_CONFIGURATION:
      usb_print_desc_config(level, (usb_desc_config_t*)desc);
      return;
    case USB_DESC_INTERFACE:
      usb_print_desc_interface(level, (usb_desc_interface_t*)desc);
      return;
    case USB_DESC_ENDPOINT:
      usb_print_desc_endpoint(level, (usb_desc_endpoint_t*)desc);
      return;
    default:
      KLOG(level, "  bLength: %d\n", desc->bLength);
      KLOG(level, "  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
      KLOG(level, "  <%d bytes of data>\n", desc->bLength);
      return;
  }
}

void usb_print_desc_dev(klog_level_t level, usb_desc_dev_t* dev_desc) {
  KLOG(level, "  bLength: %d\n", dev_desc->bLength);
  KLOG(level, "  bDescriptorType: %s (%d)\n", desc_type(dev_desc->bDescriptorType),
       dev_desc->bDescriptorType);
  KLOG(level, "  bcdUSB: 0x%x\n", dev_desc->bcdUSB);
  KLOG(level, "  bDeviceClass: 0x%x\n", dev_desc->bDeviceClass);
  KLOG(level, "  bDeviceSubClass: 0x%x\n", dev_desc->bDeviceSubClass);
  KLOG(level, "  bDeviceProtocol: 0x%x\n", dev_desc->bDeviceProtocol);
  KLOG(level, "  bMaxPacketSize0: %d\n", dev_desc->bMaxPacketSize0);
  KLOG(level, "  idVendor: 0x%x\n", dev_desc->idVendor);
  KLOG(level, "  idProduct: 0x%x\n", dev_desc->idProduct);
  KLOG(level, "  bcdDevice: 0x%x\n", dev_desc->bcdDevice);
  KLOG(level, "  iManufacturer: 0x%x\n", dev_desc->iManufacturer);
  KLOG(level, "  iProduct: 0x%x\n", dev_desc->iProduct);
  KLOG(level, "  iSerialNumber: 0x%x\n", dev_desc->iSerialNumber);
  KLOG(level, "  bNumConfigurations: %d\n", dev_desc->bNumConfigurations);
}

void usb_print_desc_config(klog_level_t level, usb_desc_config_t* desc) {
  KLOG(level, "  bLength: %d\n", desc->bLength);
  KLOG(level, "  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  KLOG(level, "  wTotalLength: %d\n", desc->wTotalLength);
  KLOG(level, "  bNumInterfaces: %d\n", desc->bNumInterfaces);
  KLOG(level, "  bConfigurationValue: 0x%x\n", desc->bConfigurationValue);
  KLOG(level, "  iConfiguration: 0x%x\n", desc->iConfiguration);
  KLOG(level, "  bmAttributes: 0x%x\n", desc->bmAttributes);
  KLOG(level, "  bMaxPower: %d\n", desc->bMaxPower);
}

void usb_print_desc_interface(klog_level_t level, usb_desc_interface_t* desc) {
  KLOG(level, "  bLength: %d\n", desc->bLength);
  KLOG(level, "  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  KLOG(level, "  bInterfaceNumber: %d\n", desc->bInterfaceNumber);
  KLOG(level, "  bAlternateSetting: %d\n", desc->bAlternateSetting);
  KLOG(level, "  bNumEndpoints: %d\n", desc->bNumEndpoints);
  KLOG(level, "  bInterfaceClass: 0x%x\n", desc->bInterfaceClass);
  KLOG(level, "  bInterfaceSubClass: 0x%x\n", desc->bInterfaceSubClass);
  KLOG(level, "  bInterfaceProtocol: 0x%x\n", desc->bInterfaceProtocol);
  KLOG(level, "  iInterface: %d\n", desc->iInterface);
}

void usb_print_desc_endpoint(klog_level_t level, usb_desc_endpoint_t* desc) {
  KLOG(level, "  bLength: %d\n", desc->bLength);
  KLOG(level, "  bDescriptorType: %s (%d)\n", desc_type(desc->bDescriptorType), desc->bDescriptorType);
  KLOG(level, "  bEndpointAddress: %d (%s)\n", desc->bEndpointAddress & 0x0F,
       desc->bEndpointAddress & USB_DESC_ENDPOINT_DIR_IN ? "IN" : "OUT");
  KLOG(level, "  bmAttributes: 0x%x\n", desc->bmAttributes);
  KLOG(level, "  wMaxPacketSize: %d\n", desc->wMaxPacketSize);
  KLOG(level, "  bInterval: %d\n", desc->bInterval);
}
