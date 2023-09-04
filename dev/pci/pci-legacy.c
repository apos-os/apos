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

#include "common/arch-config.h"
#include "common/config.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/io.h"
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci-internal.h"
#include "memory/kmalloc.h"

// IO ports for manipulating the PCI bus.
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

static const devio_t kPciIo = {IO_PORT, 0};

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
uint32_t pci_legacy_read_config(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t reg_offset) {
  io_write32(kPciIo, PCI_CONFIG_ADDR,
             make_cmd(bus, device, function, reg_offset));
  return io_read32(kPciIo, PCI_CONFIG_DATA);
}

void pci_legacy_write_config(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t reg_offset, uint32_t value) {
  io_write32(kPciIo, PCI_CONFIG_ADDR,
             make_cmd(bus, device, function, reg_offset));
  io_write32(kPciIo, PCI_CONFIG_DATA, value);
}

// Read config data for a single (bus, device, function) tuple.  Returns 0 if
// successful.
static void pci_read_device(uint8_t bus, uint8_t device, uint8_t function,
                            pci_device_t* pcidev) {
  pcidev->type = PCI_DEV_LEGACY;
  pcidev->bus = bus;
  pcidev->device = device;
  pcidev->function = function;

  uint32_t data = pci_legacy_read_config(bus, device, function, 0x0);
  pcidev->device_id = (data >> 16) & 0x0000FFFF;
  pcidev->vendor_id = data & 0x0000FFFF;

  if (data == 0xFFFFFFFF) {
    return;
  }

  pci_read_status(pcidev);

  data = pci_legacy_read_config(bus, device, function, 0x08);
  pcidev->class_code = (data >> 24) & 0x000000FF;
  pcidev->subclass_code = (data >> 16) & 0x000000FF;
  pcidev->prog_if = (data >> 8) & 0x000000FF;

  data = pci_legacy_read_config(bus, device, function, 0x0C);
  pcidev->header_type = (data >> 16) & 0x000000FF;

  for (int i = 0; i < PCI_NUM_BARS; ++i) {
    pcidev->bar[i].bar =
        pci_legacy_read_config(bus, device, function, 0x10 + 0x04 * i);
    const int bar_type = (pcidev->bar[i].bar & 0x3);
    switch (bar_type) {
      case 0:
        pcidev->bar[i].type = PCIBAR_MEM32;
        pcidev->bar[i].io.type = IO_MEMORY;
        break;
      case 1:
        pcidev->bar[i].type = PCIBAR_IO;
        pcidev->bar[i].io.type = IO_PORT;
        break;

      default:
        klogfm(KL_PCI, DFATAL, "Unsupported bar type %d\n", bar_type);
        return;
    }

    uint32_t bar_addr = pcidev->bar[i].bar & ~0x3;
    if (!bar_addr) {
      pcidev->bar[i].valid = false;
      pcidev->bar[i].io.base = 0;
    } else {
      pcidev->bar[i].valid = true;
      // TODO(aoates): fix this support on x86 systems --- this should be a
      // _virtual_, not physical, address, but they don't currently fit in the
      // physical memory map.
      pcidev->bar[i].io.base = bar_addr;
    }
  }

  data = pci_legacy_read_config(bus, device, function, 0x3C);
  pcidev->interrupt_line = data & 0x000000FF;
  pcidev->interrupt_pin = (data >> 8) & 0x000000FF;
  pcidev->host_irq = pcidev->interrupt_line;
}

// Bounce function to heap-allocate the pci_device_t.
static void do_pci_add_device(const pci_device_t* d) {
  pci_device_t* d2 = (pci_device_t*)kmalloc(sizeof(pci_device_t));
  *d2 = *d;
  pci_add_device(d2);
}

// Read all functions from a (bus, device).
static void pci_check_device(uint8_t bus, uint8_t device) {
  pci_device_t pcidev;
  pci_read_device(bus, device, PCI_FUNCTION_MIN, &pcidev);
  if (pcidev.vendor_id == 0xFFFF) {
    return;
  }

  do_pci_add_device(&pcidev);
  if (pcidev.header_type & PCI_HEADER_IS_MULTIFUNCTION) {
    for (int function = PCI_FUNCTION_MIN + 1; function <= PCI_FUNCTION_MAX;
         ++function) {
      pci_read_device(bus, device, function, &pcidev);
      if (pcidev.vendor_id != 0xFFFF) {
        do_pci_add_device(&pcidev);
      }
    }
  }
}

// NOTE: little-endian dependent.
void pci_legacy_init(void) {
  if (!ARCH_SUPPORTS_IOPORT) {
    klog("Skipping legacy PCI, ioports not supported\n");
    return;
  }

  // Find all connected PCI devices.
  klogf("Scanning PCI bus...\n");
  for (unsigned int bus = PCI_BUS_MIN; bus <= PCI_BUS_MAX; ++bus) {
    for (uint8_t device = PCI_DEVICE_MIN; device <= PCI_DEVICE_MAX; ++device) {
      pci_check_device(bus, device);
    }
  }
}
