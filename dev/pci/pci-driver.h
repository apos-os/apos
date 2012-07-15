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

// Functions and data structures for use by drivers for PCI devices.
#ifndef APOO_PCI_DRIVER_H
#define APOO_PCI_DRIVER_H

#include <stdint.h>

// Represents a single (bus, device, function) tuple.  Drivers are given one of
// structures, and can manipulate and re-read portions of it using the functions
// below.
struct pci_device {
  uint8_t bus;
  uint8_t device;
  uint8_t function;

  uint16_t device_id;
  uint16_t vendor_id;

  uint16_t status;
  uint16_t command;

  // Defines what type of device/controller this is (generically).
  uint8_t class_code;
  uint8_t subclass_code;
  uint8_t prog_if;

  uint8_t header_type;

  uint32_t base_address[6];

  // TODO(aoates): base addresses, BIST, etc
};
typedef struct pci_device pci_device_t;

// Given a PCI device (with bus, device, and function set), read it's status and
// command fields.
void pci_read_status(pci_device_t* pcidev);

// Set the values of the status and command registers for the given device.
//
// NOTE: you should call pci_read_status() first, then only modify the bits you
// need to before invoking this.
void pci_write_status(pci_device_t* pcidev);

#endif
