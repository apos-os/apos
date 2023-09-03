// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "dev/pci/pcie.h"

#include "arch/dev/irq.h"
#include "common/errno.h"
#include "common/klog.h"
#include "common/types.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/interrupts.h"
#include "dev/io.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci-internal.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"

#define KLOG(...) klogfm(KL_PCI, __VA_ARGS__)

typedef struct {
  devio_t ecam;
  size_t ecam_len;
} pcie_t;

static pcie_t g_pcie;
static bool g_pcie_found = false;

typedef struct {
  pci_device_t pub;

  devio_t cfg_io;
} pcie_device_t;

typedef struct {
  uint16_t vendor_id;
  uint16_t device_id;
  uint16_t command;
  uint16_t status;
  uint8_t revid;
  uint8_t prof_if;
  uint8_t subclass;
  uint8_t class;
  uint8_t cache_line_s;
  uint8_t lat_timer;
  uint8_t header_type;
  uint8_t bist;
  uint32_t bars[6];
  uint32_t _ignored[5];
  uint8_t interrupt_line;
  uint8_t interrupt_pin;
  uint16_t _ignored2;
} __attribute__((packed)) pci_conf_t;
_Static_assert(sizeof(pci_conf_t) == 64, "bad pci_conf_t");

// Return the offset (in bytes) of the configuration space for the given BDF.
static size_t conf_offset(int bus, int device, int func) {
  const size_t kConfSize = 4096;
  const size_t dev_idx = bus * PCI_DEVICES_PER_BUS + device;
  const size_t func_idx = dev_idx * PCI_FUNCTIONS_PER_DEVICE + func;
  return func_idx * kConfSize;
}

static pcie_device_t* read_device(pcie_t* pcie, int bus, int device,
                                  int function) {
  size_t offset = conf_offset(bus, device, 0);
  if (offset > pcie->ecam_len) {
    return NULL;
  }

  uint32_t val = io_read32(pcie->ecam, offset);
  if (val == 0xffffffff) {
    return NULL;
  }

  pcie_device_t* pdev = (pcie_device_t*)kmalloc(sizeof(pcie_device_t));
  pci_conf_t* header = (pci_conf_t*)kmalloc_aligned(sizeof(pci_conf_t), 4);
  void* _x = header;  // Trick -Werror=address-of-packed-member
  uint32_t* header_u32 = (uint32_t*)_x;
  for (size_t i = 0; i < sizeof(pci_conf_t) / sizeof(uint32_t); ++i) {
    header_u32[i] = io_read32(pcie->ecam, offset + i * sizeof(uint32_t));
  }

  pdev->pub.bus = bus;
  pdev->pub.device = device;
  pdev->pub.function = 0;
  pdev->pub.device_id = header->device_id;
  pdev->pub.vendor_id = header->vendor_id;
  pdev->pub.status = header->status;
  pdev->pub.command = header->command;
  pdev->pub.class_code = header->class;
  pdev->pub.subclass_code = header->subclass;
  pdev->pub.prog_if = header->prof_if;
  pdev->pub.header_type = header->header_type;
  for (int bar = 0; bar < 6; ++bar) {
    pdev->pub.bar[bar].bar = header->bars[bar];
    pdev->pub.bar[bar].valid = false;
  }
  pdev->pub.interrupt_line = header->interrupt_line;
  pdev->pub.interrupt_pin = header->interrupt_pin;
  kfree(header);
  return pdev;
}

static void pci_check_device(pcie_t* pcie, int bus, int device) {
  pcie_device_t* pdev = read_device(pcie, bus, device, 0);
  if (!pdev) return;

  pci_add_device(&pdev->pub);

  if (pdev->pub.header_type & PCI_HEADER_IS_MULTIFUNCTION) {
    for (int function = PCI_FUNCTION_MIN + 1; function <= PCI_FUNCTION_MAX;
         ++function) {
      pcie_device_t* funcdev = read_device(pcie, bus, device, function);
      if (funcdev) {
        pci_add_device(&funcdev->pub);
      }
    }
  }
}

int pcie_init(void) {
  if (!g_pcie_found) {
    KLOG(INFO, "No PCIe controller found\n");
    return -1;
  }

  // Find all devices.
  for (unsigned int bus = PCI_BUS_MIN; bus <= PCI_BUS_MAX; ++bus) {
    for (uint8_t device = PCI_DEVICE_MIN; device <= PCI_DEVICE_MAX; ++device) {
      pci_check_device(&g_pcie, bus, device);
    }
  }

  // TODO(aoates): map interrupts
  // TODO(aoates): for all devices, allocate any BARs as necessary
  return 0;
}

int pcie_controller_driver(const dt_tree_t* tree, const dt_node_t* node,
                           const char* node_path, dt_driver_info_t* driver) {
  KLOG(INFO, "Initializing PCIe controller on node %s\n", node_path);
  g_pcie_found = true;

  dt_regval_t reg[10];
  int result = dt_parse_reg(node, reg, 10);
  if (result <= 0) {
    KLOG(WARNING, "Unable to parse reg from PCIe controller: %s\n",
         errorname(-result));
    return result;
  }

  g_pcie.ecam.type = IO_MEMORY;
  g_pcie.ecam.base = phys2virt(reg[0].base);
  g_pcie.ecam_len = reg[0].len;

  // TODO(aoates): create memory map from ranges

  return 0;
}
