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

// Standard USB descriptors.  See section 9 of the USB 2.0 spec.
#ifndef APOO_DEV_USB_DESCRIPTOR_H
#define APOO_DEV_USB_DESCRIPTOR_H

#include <stddef.h>
#include <stdint.h>

// Standard descriptor "interface".  All standard descriptors start with a
// length and type, followed by the rest of the data.
struct usb_desc_base {
  uint8_t bLength;  // Size of the descriptor in bytes.
  uint8_t bDescriptorType;  // Must be USB_DESC_DEVICE.

  // The rest of the descriptor.
  char data[];
};
typedef struct usb_desc_base usb_desc_base_t;

// Descriptor linked list.
struct usb_desc_list_node {
  struct usb_desc_list_node* next;
  usb_desc_base_t* desc;
};
typedef struct usb_desc_list_node usb_desc_list_node_t;

// Descriptor types.  See page 251 of the USB 2.0 spec.
#define USB_DESC_DEVICE 1
#define USB_DESC_CONFIGURATION 2
#define USB_DESC_STRING 3
#define USB_DESC_INTERFACE 4
#define USB_DESC_ENDPOINT 5
#define USB_DESC_DEVICE_QUALIFIER 6
#define USB_DESC_OTHER_SPEED_CONFIGURATION 7
#define USB_DESC_INTERFACE_POWER 8

// Device descriptor.  One per device.
struct usb_desc_dev {
  uint8_t bLength;  // Size of the descriptor in bytes.
  uint8_t bDescriptorType;  // Must be USB_DESC_DEVICE.
  uint16_t bcdUSB;  // USB version.
  uint8_t bDeviceClass;
  uint8_t bDeviceSubClass;
  uint8_t bDeviceProtocol;
  uint8_t bMaxPacketSize0;
  uint16_t idVendor;
  uint16_t idProduct;
  uint16_t bcdDevice;
  uint8_t iManufacturer;
  uint8_t iProduct;
  uint8_t iSerialNumber;
  uint8_t bNumConfigurations;
} __attribute__((packed));
typedef struct usb_desc_dev usb_desc_dev_t;

// Bits in in the bmAttributes field in usb_desc_config_t.
#define USB_DESC_CONFIG_BMATTR_SELF_POWERED  0x40
#define USB_DESC_CONFIG_BMATTR_REMOTE_WAKEUP 0x20

// Configuration descriptor.  The device descriptor's bNumConfigurations field
// tells how many there are in a given device.
struct usb_desc_config {
  uint8_t bLength;  // Size of the descriptor in bytes.
  uint8_t bDescriptorType;  // Must be USB_DESC_CONFIGURATION.
  // Total length of data returned for this configuration, including the
  // combined length of all other descriptors returned.
  uint16_t wTotalLength;
  uint8_t bNumInterfaces;  // Must be at least 1.
  uint8_t bConfigurationValue;
  uint8_t iConfiguration;
  uint8_t bmAttributes;
  uint8_t bMaxPower;  // Max power in 2 mA units.
} __attribute__((packed));
typedef struct usb_desc_config usb_desc_config_t;

// Interface descriptor.  There are bNumInterfaces interfaces for each
// configuration.
struct usb_desc_interface {
  uint8_t bLength;  // Size of the descriptor in bytes.
  uint8_t bDescriptorType;  // Must be USB_DESC_INTERFACE.
  uint8_t bInterfaceNumber;
  uint8_t bAlternateSetting;
  uint8_t bNumEndpoints;  // If zero, only the default control pipe is used.
  uint8_t bInterfaceClass;
  uint8_t bInterfaceSubClass;
  uint8_t bInterfaceProtocol;
  uint8_t iInterface;
} __attribute__((packed));
typedef struct usb_desc_interface usb_desc_interface_t;

// Direction for an endpoint (1 == IN).
#define USB_DESC_ENDPOINT_DIR_IN 0x80

// Fields in the bmAttributes field of usb_desc_endpoint_t struct.
#define USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_MASK 0x03
#define USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_CONTROL 0x00
#define USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_ISO 0x01
#define USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_BULK 0x02
#define USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_INTERRUPT 0x03

#define USB_DESC_ENDPOINT_BMATTR_SYNC_TYPE_MASK  0x0C
#define USB_DESC_ENDPOINT_BMATTR_USAGE_TYPE_MASK 0x30

#define USB_DESC_ENDPOINT_MAX_PACKET_SIZE_MASK 0x3F

// Endpoint descriptor.  Each interface (or alternate setting for an interface)
// has an associated set of endpoints.
struct usb_desc_endpoint {
  uint8_t bLength;  // Size of the descriptor in bytes.
  uint8_t bDescriptorType;  // Must be USB_DESC_ENDPOINT.
  uint8_t bEndpointAddress;  // Bit 3..0 is the address, bit 7 indicates IN.
  uint8_t bmAttributes;
  uint16_t wMaxPacketSize;
  uint8_t bInterval;
} __attribute__((packed));
typedef struct usb_desc_endpoint usb_desc_endpoint_t;

// Utility functions.

// Parse a set of descriptors returned by a device sent GET_DESCRIPTOR(CONFIG,
// |config_index|).  Creates a descriptor list (e.g. to put in a device_t) and
// returns it in |list_out|, which should point to an empty list node to be used
// as the list head.  Returns -errno if it couldn't be parsed.
int usb_parse_descriptors(usb_desc_list_node_t* list_out,
                          void* buf, size_t buflen);

// Print descriptors.
void usb_print_desc_list(usb_desc_list_node_t* list);

void usb_print_desc(usb_desc_base_t* desc);
void usb_print_desc_dev(usb_desc_dev_t* desc);
void usb_print_desc_config(usb_desc_config_t* desc);
void usb_print_desc_interface(usb_desc_interface_t* desc);
void usb_print_desc_endpoint(usb_desc_endpoint_t* desc);

#endif
