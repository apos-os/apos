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

#include <stdbool.h>
#include <stdint.h>

#include "arch/dev/irq.h"
#include "dev/io.h"

typedef enum {
  PCI_CMD_IO_SPACE_ENABLE = 0x01,
  PCI_CMD_MEMORY_SPACE_ENABLE = 0x02,
  PCI_CMD_BUSMASTER_ENABLE = 0x04,
} pci_command_bits_t;

typedef enum {
  PCIBAR_IO = 1,
  PCIBAR_MEM32,
  PCIBAR_MEM64,
} pci_bar_type_t;

typedef struct {
  bool valid;  // Whether this BAR can be used.
  uint32_t bar;  // Raw BAR value.  Should not generally be used.

  // The PCI type of the BAR.  May not match the devio type!  For example, a PCI
  // IO-port region may be memory-mapped to the host.
  pci_bar_type_t type;

  // devio used to access the BAR, iff valid is true.  Drivers should use this
  // to access the BAR.
  devio_t io;
} pci_bar_t;

#define PCI_NUM_BARS 6

typedef enum {
  PCI_DEV_LEGACY = 1,
  PCI_DEV_PCIE,
} pci_dev_type_t;

// Represents a single (bus, device, function) tuple.  Drivers are given one of
// structures, and can manipulate and re-read portions of it using the functions
// below.
struct pci_device {
  pci_dev_type_t type;

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

  pci_bar_t bar[PCI_NUM_BARS];

  // The interrupt line and pin the device is currently configured to use.
  // These are PCI-relative, and should not be used by driver code.
  uint8_t interrupt_line;
  uint8_t interrupt_pin;

  // Host-side interrupt for this device, or zero.
  irq_t host_irq;
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

// Read or write an arbitrary register from the PCI configuration space.
uint32_t pci_read_register(pci_device_t* pcidev, uint8_t reg_offset);
void pci_write_register(pci_device_t* pcidev, uint8_t reg_offset,
                        uint32_t value);


#endif
