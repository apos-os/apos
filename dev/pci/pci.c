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

#include <stdint.h>

#include "arch/common/io.h"
#include "common/config.h"
#include "common/kassert.h"
#include "common/klog.h"
#if ENABLE_ETHERNET
#include "dev/net/rtl8139.h"
#endif
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/piix.h"
#if ENABLE_USB
#include "dev/pci/usb_uhci.h"
#endif
#include "memory/kmalloc.h"

// IO ports for manipulating the PCI bus.
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

#define PCI_BUS_MIN 0x00
#define PCI_BUS_MAX 0xFF
#define PCI_DEVICE_MIN 0x00
#define PCI_DEVICE_MAX 0x1F
#define PCI_FUNCTION_MIN 0x00
#define PCI_FUNCTION_MAX 0x07
#define PCI_REGISTER_MIN 0x00
#define PCI_REGISTER_MAX 0xFC

#define PCI_STATUS_REG_OFFSET 0x04

#define PCI_HEADER_IS_MULTIFUNCTION 0x80

#define PCI_MAX_DEVICES 40
static pci_device_t g_pci_devices[PCI_MAX_DEVICES];
static int g_pci_count = 0;

// Static table of drivers.
#define PCI_DRIVER_VENDOR 1
#define PCI_DRIVER_CLASS 2
struct pci_driver {
  // Determines how the driver is matched.  Should be either PCI_DRIVER_VENDOR
  // (meaning device_id and vendor_id are checked), or PCI_DRIVER_CLASS (meaning
  // class_code, subclass_code and prog_if are checked).
  int type;

  uint16_t device_id;
  uint16_t vendor_id;

  uint8_t class_code;
  uint8_t subclass_code;
  uint8_t prog_if;

  void (*driver)(pci_device_t*);
};
typedef struct pci_driver pci_driver_t;

static pci_driver_t PCI_DRIVERS[] = {
  // PCI <-> ISA controller
  { PCI_DRIVER_VENDOR, 0x7000, 0x8086, 0, 0, 0, &pci_piix_driver_init },
  // PCI <-> IDE controller
  { PCI_DRIVER_VENDOR, 0x7010, 0x8086, 0, 0, 0, &pci_piix_driver_init },

#if ENABLE_USB
  // UHCI USB Host Controller.
  { PCI_DRIVER_CLASS, 0x0, 0x0, 0x0C, 0x03, 0x00, &usb_uhci_pci_init },
#endif

#if ENABLE_ETHERNET
  // RTL 8139 network card.
  { PCI_DRIVER_VENDOR, 0x8139, 0x10ec, 0, 0, 0, &pci_rtl8139_init },
#endif

  { 0, 0xFFFF, 0xFFFF, 0xFF, 0xFF, 0xFF, 0x0},
};

static inline uint32_t make_cmd(uint8_t bus, uint8_t device,
                                uint8_t function, uint8_t reg_offset) {
  KASSERT((device & 0xE0) == 0);
  KASSERT((function & 0xF8) == 0);
  KASSERT((reg_offset & 0x03) == 0);
  return (0x80000000 | // Enable
          (bus << 16) |
          (device << 11) |
          (function << 8) |
          (reg_offset & 0xFC));
}

// Read a word from a PCI config register.
static uint32_t pci_read_config(uint8_t bus, uint8_t device,
                                uint8_t function, uint8_t reg_offset) {
  outl(PCI_CONFIG_ADDR, make_cmd(bus, device, function, reg_offset));
  return inl(PCI_CONFIG_DATA);
}

static void pci_write_config(uint8_t bus, uint8_t device,
                             uint8_t function, uint8_t reg_offset,
                             uint32_t value) {
  outl(PCI_CONFIG_ADDR, make_cmd(bus, device, function, reg_offset));
  outl(PCI_CONFIG_DATA, value);
}

// Read config data for a single (bus, device, function) tuple.  Returns 0 if
// successful.
static void pci_read_device(uint8_t bus, uint8_t device, uint8_t function,
                            pci_device_t* pcidev) {
  pcidev->bus = bus;
  pcidev->device = device;
  pcidev->function = function;

  uint32_t data = pci_read_config(bus, device, function, 0x0);
  pcidev->device_id = (data >> 16) & 0x0000FFFF;
  pcidev->vendor_id = data & 0x0000FFFF;

  if (data == 0xFFFFFFFF) {
    return;
  }

  pci_read_status(pcidev);

  data = pci_read_config(bus, device, function, 0x08);
  pcidev->class_code = (data >> 24) & 0x000000FF;
  pcidev->subclass_code = (data >> 16) & 0x000000FF;
  pcidev->prog_if = (data >> 8) & 0x000000FF;

  data = pci_read_config(bus, device, function, 0x0C);
  pcidev->header_type = (data >> 16) & 0x000000FF;

  for (int i = 0; i < 6; ++i) {
    pcidev->base_address[i] = pci_read_config(bus, device, function,
                                              0x10 + 0x04 * i);
  }

  data = pci_read_config(bus, device, function, 0x3C);
  pcidev->interrupt_line = data & 0x000000FF;
  pcidev->interrupt_pin = (data >> 8) & 0x000000FF;
}

void pci_read_status(pci_device_t* pcidev) {
  uint32_t data = pci_read_config(pcidev->bus, pcidev->device,
                                  pcidev->function, PCI_STATUS_REG_OFFSET);
  pcidev->status = (data >> 16) & 0x0000FFFF;
  pcidev->command = data & 0x0000FFFF;
}

void pci_write_status(pci_device_t* pcidev) {
  uint32_t data = ((pcidev->status & 0x0000FFFF) << 16) |
      (pcidev->command & 0x0000FFFF);
  pci_write_config(pcidev->bus, pcidev->device, pcidev->function,
                   PCI_STATUS_REG_OFFSET, data);
}

static void pci_print_device(pci_device_t* pcidev) {
  klogf("    %d.%d(%d):  dev_id: 0x%x  vendor_id: 0x%x"
        "  type: (0x%x, 0x%x, 0x%x)  intr: %d (pin %d)\n",
        (uint32_t)pcidev->bus, (uint32_t)pcidev->device,
        (uint32_t)pcidev->function, (uint32_t)pcidev->device_id,
        (uint32_t)pcidev->vendor_id, (uint32_t)pcidev->class_code,
        (uint32_t)pcidev->subclass_code, (uint32_t)pcidev->prog_if,
        (uint32_t)pcidev->interrupt_line, (uint32_t)pcidev->interrupt_pin);
}

static void pci_add_device(pci_device_t* pcidev) {
  if (g_pci_count >= PCI_MAX_DEVICES) {
    klogf("WARNING: too many PCI devices found (maximum is %d)\n",
          PCI_MAX_DEVICES);
    return;
  }
  g_pci_devices[g_pci_count++] = *pcidev;
}

// Read all functions from a (bus, device).
static void pci_check_device(uint8_t bus, uint8_t device) {
  pci_device_t pcidev;
  pci_read_device(bus, device, PCI_FUNCTION_MIN, &pcidev);
  if (pcidev.vendor_id == 0xFFFF) {
    return;
  }

  if (pcidev.header_type & PCI_HEADER_IS_MULTIFUNCTION) {
    pci_add_device(&pcidev);
    for (int function = PCI_FUNCTION_MIN + 1; function <= PCI_FUNCTION_MAX;
         ++function) {
      pci_read_device(bus, device, function, &pcidev);
      if (pcidev.vendor_id != 0xFFFF) {
        pci_add_device(&pcidev);
      }
    }
  } else {
    pci_add_device(&pcidev);
  }
}

// NOTE: little-endian dependent.
void pci_init(void) {
  // Find all connected PCI devices.
  klogf("Scanning PCI bus...\n");
  for (unsigned int bus = PCI_BUS_MIN; bus <= PCI_BUS_MAX; ++bus) {
    for (uint8_t device = PCI_DEVICE_MIN; device <= PCI_DEVICE_MAX; ++device) {
      pci_check_device(bus, device);
    }
  }

  klogf("  found %d devices:\n", g_pci_count);
  for (int i = 0; i < g_pci_count; ++i) {
    pci_print_device(&g_pci_devices[i]);
  }

  // Invoke drivers.
  for (int i = 0; i < g_pci_count; ++i) {
    pci_driver_t* driver = &PCI_DRIVERS[0];
    while (driver->vendor_id != 0xFFFF) {
      if (driver->type == PCI_DRIVER_VENDOR &&
          driver->vendor_id == g_pci_devices[i].vendor_id &&
          driver->device_id == g_pci_devices[i].device_id) {
        driver->driver(&g_pci_devices[i]);
      } else if (driver->type == PCI_DRIVER_CLASS &&
                 driver->class_code == g_pci_devices[i].class_code &&
                 driver->subclass_code == g_pci_devices[i].subclass_code &&
                 driver->prog_if == g_pci_devices[i].prog_if) {
        driver->driver(&g_pci_devices[i]);
      }
      driver++;
    }
  }
}

uint32_t pci_read_register(pci_device_t* pcidev, uint8_t reg_offset) {
  return pci_read_config(pcidev->bus, pcidev->device, pcidev->function,
                         reg_offset);
}

void pci_write_register(pci_device_t* pcidev, uint8_t reg_offset,
                        uint32_t value) {
  return pci_write_config(pcidev->bus, pcidev->device, pcidev->function,
                          reg_offset, value);
}
