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

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/pci/pcie.h"
#if ENABLE_ETHERNET
#include "dev/net/rtl8139.h"
#endif
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci-internal.h"
#include "dev/pci/pci-legacy.h"
#include "dev/pci/piix.h"
#if ENABLE_USB
#include "dev/pci/usb_uhci.h"
#endif

#if ENABLE_NVME
#include "dev/nvme/controller.h"
#endif

#define PCI_MAX_DEVICES 40
static pci_device_t* g_pci_devices[PCI_MAX_DEVICES];
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

  // TODO(aoates): fix PCI memory mapped BAR bug and enable NVMe driver for x86.
#if ENABLE_NVME && ARCH == ARCH_riscv64
  { PCI_DRIVER_CLASS, 0x0, 0x0, 0x1, 0x8, 0x2, &nvme_ctrl_pci_init },
#endif

  { 0, 0xFFFF, 0xFFFF, 0xFF, 0xFF, 0xFF, 0x0},
};

void pci_print_device(pci_device_t* pcidev) {
  klogf(
      "    %d.%d(%d):  dev_id: 0x%x  vendor_id: 0x%x"
      "  type: (0x%x, 0x%x, 0x%x)  irq: %d (line %d, pin %d)\n",
      (uint32_t)pcidev->bus, (uint32_t)pcidev->device,
      (uint32_t)pcidev->function, (uint32_t)pcidev->device_id,
      (uint32_t)pcidev->vendor_id, (uint32_t)pcidev->class_code,
      (uint32_t)pcidev->subclass_code, (uint32_t)pcidev->prog_if,
      pcidev->host_irq, (uint32_t)pcidev->interrupt_line,
      (uint32_t)pcidev->interrupt_pin);
}

void pci_add_device(pci_device_t* pcidev) {
  if (g_pci_count >= PCI_MAX_DEVICES) {
    klogf("WARNING: too many PCI devices found (maximum is %d)\n",
          PCI_MAX_DEVICES);
    return;
  }
  g_pci_devices[g_pci_count++] = pcidev;
}

void pci_init(void) {
  // TODO(aoates): support ECAM-based MMIO PCIe.
  pci_legacy_init();
  pcie_init();

  klogf("  found %d devices:\n", g_pci_count);
  for (int i = 0; i < g_pci_count; ++i) {
    pci_print_device(g_pci_devices[i]);
  }

  // Invoke drivers.
  for (int i = 0; i < g_pci_count; ++i) {
    pci_driver_t* driver = &PCI_DRIVERS[0];
    while (driver->vendor_id != 0xFFFF) {
      if (driver->type == PCI_DRIVER_VENDOR &&
          driver->vendor_id == g_pci_devices[i]->vendor_id &&
          driver->device_id == g_pci_devices[i]->device_id) {
        driver->driver(g_pci_devices[i]);
      } else if (driver->type == PCI_DRIVER_CLASS &&
                 driver->class_code == g_pci_devices[i]->class_code &&
                 driver->subclass_code == g_pci_devices[i]->subclass_code &&
                 driver->prog_if == g_pci_devices[i]->prog_if) {
        driver->driver(g_pci_devices[i]);
      }
      driver++;
    }
  }
}

void pci_read_status(pci_device_t* pcidev) {
  uint32_t data = pci_read_register(pcidev, PCI_STATUS_REG_OFFSET);
  pcidev->status = (data >> 16) & 0x0000FFFF;
  pcidev->command = data & 0x0000FFFF;
}

void pci_write_status(pci_device_t* pcidev) {
  uint32_t data = ((pcidev->status & 0x0000FFFF) << 16) |
      (pcidev->command & 0x0000FFFF);
  pci_write_register(pcidev, PCI_STATUS_REG_OFFSET, data);
}

uint32_t pci_read_register(pci_device_t* pcidev, uint8_t reg_offset) {
  switch (pcidev->type) {
    case PCI_DEV_LEGACY:
      return pci_legacy_read_config(pcidev->bus, pcidev->device,
                                    pcidev->function, reg_offset);
    case PCI_DEV_PCIE:
      return pcie_read_config(pcidev, reg_offset);
  }
  die("unreachable");
}

void pci_write_register(pci_device_t* pcidev, uint8_t reg_offset,
                        uint32_t value) {
  switch (pcidev->type) {
    case PCI_DEV_LEGACY:
      return pci_legacy_write_config(pcidev->bus, pcidev->device,
                                     pcidev->function, reg_offset, value);
    case PCI_DEV_PCIE:
      return pcie_write_config(pcidev, reg_offset, value);
  }
  die("unreachable");
}
