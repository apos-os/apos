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
#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "common/types.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/interrupts.h"
#include "dev/io.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci-internal.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"

#define KLOG(...) klogfm(KL_PCI, __VA_ARGS__)

typedef addr64_t pci_addr_t;

typedef struct {
  pci_device_t pub;

  devio_t cfg_io;
} pcie_device_t;

typedef struct {
  pci_bar_type_t type;
  bool prefetchable;
  pci_addr_t pci_base;
  addr_t host_base;
  addr64_t len;

  // The next free offset in the range.
  addr64_t next_free;
} pcie_mmap_entry_t;

#define PCIE_MMAP_ENTRIES 10
typedef struct {
  int num_ranges;
  pcie_mmap_entry_t ranges[PCIE_MMAP_ENTRIES];
} pcie_mmap_t;

typedef struct pcie {
  devio_t ecam;
  size_t ecam_len;

  pcie_mmap_t mmap;

  // Min and maximum bus IDs on this controller.
  int bus_min, bus_max;

  // Opaque controller data.
  void* ctrl_data;

  // Controller function to translate a device's interrupt data into a host IRQ.
  int (*translate_irq)(struct pcie* pcie, pcie_device_t* dev);
} pcie_t;

static pcie_t g_pcie;
static bool g_pcie_found = false;

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

// Read the data from the ECAM for the given BDF.
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

  pdev->pub.type = PCI_DEV_PCIE;
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
  pdev->pub.host_irq = 0;
  pdev->cfg_io.base = pcie->ecam.base + offset;
  pdev->cfg_io.type = pcie->ecam.type;
  kfree(header);
  return pdev;
}

static const char* bartype2str(pci_bar_type_t t) {
  switch (t) {
    case PCIBAR_IO: return "IO";
    case PCIBAR_MEM32: return "MEM32";
    case PCIBAR_MEM64: return "MEM64";
  }
  die("bad pci_bar_type_t");
}

static void allocate_bars(pcie_t* pcie, pcie_device_t* dev) {
  bool skip_next = false;
  for (int i = 0; i < PCI_NUM_BARS; ++i) {
    if (skip_next) {
      skip_next = false;
      continue;
    }

    pci_bar_t* bar = &dev->pub.bar[i];
    uint32_t bar_addr_mask;
    KASSERT(pci_parse_bar(bar->bar, bar, &bar_addr_mask) == 0);
    if (bar->type == PCIBAR_MEM64) {
      KASSERT(i < PCI_NUM_BARS - 1);
    }
    KASSERT_MSG(bar->io.base == 0, "Pre-allocated BARs are not supported");

    size_t bar_offset = offsetof(pci_conf_t, bars) + i * sizeof(uint32_t);
    io_write32(dev->cfg_io, bar_offset, 0xffffffff);
    uint32_t newval = io_read32(dev->cfg_io, bar_offset);
    newval &= bar_addr_mask;
    size_t bar_len = (0xffffffff - newval) + 1;
    if (bar_len == 0) {
      continue;
    }
    // Sanity check (we don't check upper bits of 64-bit BARs).
    KASSERT(bar_len < 0x100000);

    // Find a matching memory area.
    int range_idx = -1;
    for (int j = 0; j < pcie->mmap.num_ranges; ++j) {
      if (pcie->mmap.ranges[j].type == bar->type &&
          pcie->mmap.ranges[j].prefetchable == bar->prefetchable) {
        range_idx = j;
        break;
      }
    }
    if (range_idx < 0) {
      die("Found unallocatable BAR");
    }

    // Allocate a chunk of the appropriate size and alignment.
    pcie_mmap_entry_t* range = &pcie->mmap.ranges[range_idx];
    range->next_free = align_up(range->next_free, bar_len);
    if (range->next_free >= range->len) {
      die("Not enough memory to allocate BAR");
    }

    // Update BAR in memory and PCI configuration space.
    pci_addr_t pci_addr = range->pci_base + range->next_free;
    if (range->type != PCIBAR_MEM64) {
      KASSERT(pci_addr <= UINT32_MAX);
    }
    io_write32(dev->cfg_io, bar_offset, pci_addr);
    if (range->type == PCIBAR_MEM64) {
      skip_next = true;
      io_write32(dev->cfg_io, bar_offset + sizeof(uint32_t), pci_addr >> 32);
    }
    bar->io.base = phys2virt(range->host_base + range->next_free);
    range->next_free += bar_len;
    bar->valid = true;
    KLOG(INFO,
         "  Allocated BAR %d: %s 0x%zx bytes at 0x%" PRIxADDR
         " (pci)/0x%" PRIxADDR " (host)\n",
         i, bartype2str(bar->type), bar_len, (size_t)pci_addr, bar->io.base);

    // Enable BAR access in the PCI device.
    pci_read_status(&dev->pub);
    dev->pub.command |= PCI_CMD_IO_SPACE_ENABLE | PCI_CMD_MEMORY_SPACE_ENABLE;
    pci_write_status(&dev->pub);
  }
}

// Read device data from the ECAM and initialize data structures (e.g. BARS).
static pcie_device_t* create_device(pcie_t* pcie, int bus, int device,
                                  int function) {
  pcie_device_t* dev = read_device(pcie, bus, device, function);
  if (!dev) {
    return NULL;
  }

  allocate_bars(pcie, dev);
  pcie->translate_irq(pcie, dev);

  return dev;
}

static void pci_check_device(pcie_t* pcie, int bus, int device) {
  pcie_device_t* pdev = create_device(pcie, bus, device, 0);
  if (!pdev) return;

  pci_add_device(&pdev->pub);

  if (pdev->pub.header_type & PCI_HEADER_IS_MULTIFUNCTION) {
    for (int function = PCI_FUNCTION_MIN + 1; function <= PCI_FUNCTION_MAX;
         ++function) {
      pcie_device_t* funcdev = create_device(pcie, bus, device, function);
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
  for (int bus = g_pcie.bus_min; bus <= g_pcie.bus_max; ++bus) {
    for (uint8_t device = PCI_DEVICE_MIN; device <= PCI_DEVICE_MAX; ++device) {
      pci_check_device(&g_pcie, bus, device);
    }
  }

  return 0;
}

uint32_t pcie_read_config(pci_device_t* pcidev, uint8_t reg_offset) {
  pcie_device_t* pcie = (pcie_device_t*)pcidev;
  return io_read32(pcie->cfg_io, reg_offset);
}

void pcie_write_config(pci_device_t* pcidev, uint8_t reg_offset,
                       uint32_t value) {
  pcie_device_t* pcie = (pcie_device_t*)pcidev;
  io_write32(pcie->cfg_io, reg_offset, value);
}

typedef struct {
  const dt_tree_t* tree;
  const dt_node_t* ctrl;
} dtree_pcie_ctrl_t;

static uint64_t read64(const uint32_t* cells) {
  return ((uint64_t)btoh32(cells[0]) << 32) + btoh32(cells[1]);
}

static int parse_ranges(const dt_node_t* node, pcie_mmap_t* mmap) {
  for (int i = 0; i < PCIE_MMAP_ENTRIES; ++i) {
    kmemset(&mmap->ranges[i], 0, sizeof(pcie_mmap_entry_t));
  }

  const dt_property_t* ranges = dt_get_prop(node, "ranges");
  if (!ranges) {
    KLOG(WARNING, "PCIe controller missing ranges property\n");
    return -ENOENT;
  }

  const size_t kPciAddressCells = 3;
  const size_t kPciSizeCells = 2;
  KASSERT_MSG(node->context.address_cells == 2,
              "Only 64-bit currently supported");
  const size_t entry_cells =
      kPciAddressCells + kPciSizeCells + node->context.address_cells;
  if (ranges->val_len % (entry_cells * sizeof(uint32_t)) != 0) {
    KLOG(WARNING, "PCIe controller malformed ranges property\n");
    return -EINVAL;
  }
  const int num_entries = ranges->val_len / (entry_cells * sizeof(uint32_t));
  KASSERT(num_entries <= PCIE_MMAP_ENTRIES);

  const uint32_t* cells = (const uint32_t*)ranges->val;
  for (int i = 0; i < num_entries; ++i) {
    size_t offset = i * entry_cells;
    uint32_t phys_hi = btoh32(cells[offset]);
    pci_addr_t pci_addr = read64(cells + offset + 1);
    addr64_t host_addr = read64(cells + offset + kPciAddressCells);
    addr64_t size =
        read64(cells + offset + kPciAddressCells + node->context.address_cells);

    bool prefetchable = (phys_hi >> (24 + 6)) & 0x1;
    int spacecode = (phys_hi >> 24) & 0x3;
    KASSERT_MSG((phys_hi & 0x00FFFFFF) == 0, "Unsupported ranges address");
    // TODO(aoates): print this portably as 64-bit numbers.
    KLOG(INFO,
         "  PCIe memory region: pre=%d, type=%d, pci=0x%zx, "
         "host=0x%zx, len=0x%zx\n",
         prefetchable, spacecode, (size_t)pci_addr, (size_t)host_addr,
         (size_t)size);

    mmap->ranges[i].prefetchable = prefetchable;
    mmap->ranges[i].pci_base = pci_addr;
    mmap->ranges[i].host_base = host_addr;
    mmap->ranges[i].len = size;
    if (spacecode == 1) {
      mmap->ranges[i].type = PCIBAR_IO;
    } else if (spacecode == 2) {
      mmap->ranges[i].type = PCIBAR_MEM32;
    } else if (spacecode == 3) {
      mmap->ranges[i].type = PCIBAR_MEM64;
    } else {
      KLOG(WARNING, "Unsupported PCIe space code %d\n", spacecode);
      return -EINVAL;
    }
  }
  mmap->num_ranges = num_entries;

  return 0;
}

static int dtree_translate_irq(pcie_t* pcie, pcie_device_t* dev) {
  dtree_pcie_ctrl_t* ctrl = (dtree_pcie_ctrl_t*)pcie->ctrl_data;

  KASSERT(dev->pub.interrupt_line == 0);
  if (dev->pub.interrupt_pin == 0) {
    KLOG(DEBUG, "PCIe device %d.%d(%d) has no interrupt to map\n",
         dev->pub.bus, dev->pub.device, dev->pub.function);
    return 0;
  }

  // Construct the PCIe address.
  uint32_t pcie_addr[3];
  KASSERT(dev->pub.function <= PCI_FUNCTION_MAX);
  KASSERT(dev->pub.device <= PCI_DEVICE_MAX);
  KASSERT(dev->pub.bus <= PCI_BUS_MAX);
  pcie_addr[0] =
      dev->pub.function | (dev->pub.device << 3) | (dev->pub.bus << 8);
  pcie_addr[0] <<= 8;
  pcie_addr[1] = pcie_addr[2] = 0;

  // Construct the devicetree interrupt spec.
  dt_interrupt_t dtint;
  dtint.cells = 1;
  dtint.int_parent = ctrl->ctrl;
  dtint._int[0] = dev->pub.interrupt_pin;

  dt_interrupt_t mapped_dtint;
  const dt_node_t* irq_root = arch_irq_root();
  int result =
      dtint_map_raw(ctrl->tree, pcie_addr, 3, &dtint, irq_root, &mapped_dtint);
  if (result) {
    KLOG(WARNING, "Unable to map PCIe interrupt %d on device %d.%d(%d): %s\n",
         dev->pub.interrupt_pin, dev->pub.bus, dev->pub.device,
         dev->pub.function, errorname(-result));
    return result;
  }

  KASSERT(dev->pub.host_irq == 0);
  dev->pub.host_irq = dtint_flatten(&mapped_dtint);
  KLOG(INFO, "  Mapped PCIe device %d.%d(%d) to host IRQ %d\n", dev->pub.bus,
       dev->pub.device, dev->pub.function, dev->pub.host_irq);
  return 0;
}

static int validate_pci_props(const dt_node_t* node) {
  if (dt_get_prop_int(node, "#address-cells") != 3) {
    KLOG(WARNING, "PCIe controller #address-cells should be 3\n");
    return -EINVAL;
  }
  if (dt_get_prop_int(node, "#size-cells") != 2) {
    KLOG(WARNING, "PCIe controller #size-cells should be 2\n");
    return -EINVAL;
  }
  if (dt_get_prop_int(node, "#interrupt-cells") != 1) {
    KLOG(WARNING, "PCIe controller #interrupt-cells should be 1\n");
    return -EINVAL;
  }
  if (dt_get_prop(node, "dma-coherent") == NULL) {
    KLOG(WARNING, "PCIe controller must have dma-coherent\n");
    return -EINVAL;
  }
  if (!dt_prop_streq(node, "device_type", "pci")) {
    KLOG(WARNING, "PCIe controller has invalid device_type\n");
    return -EINVAL;
  }

  return 0;
}

int parse_bus_range(const dt_node_t* node, pcie_t* pcie) {
  const dt_property_t* prop = dt_get_prop(node, "bus-range");
  if (prop->val_len != 2 * sizeof(uint32_t)) {
    KLOG(WARNING, "PCIe controller has invalid bus-range property\n");
    return -EINVAL;
  }

  const uint32_t* cells = (const uint32_t*)prop->val;
  pcie->bus_min = btoh32(cells[0]);
  pcie->bus_max = btoh32(cells[1]);
  if (pcie->bus_min < PCI_BUS_MIN || pcie->bus_min > PCI_BUS_MAX ||
      pcie->bus_max < PCI_BUS_MIN || pcie->bus_max > PCI_BUS_MAX) {
    KLOG(WARNING, "PCIe controller has invalid bus-range property\n");
    return -ERANGE;
  }

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

  // Do some basic validation of the node properties.  Some of these may not be
  // invalid (such as not having a dma-coherent property), but we don't handle
  // them properly currently.
  result = validate_pci_props(node);
  if (result) {
    return result;
  }

  g_pcie.ecam.type = IO_MEMORY;
  g_pcie.ecam.base = phys2virt(reg[0].base);
  g_pcie.ecam_len = reg[0].len;
  dtree_pcie_ctrl_t* ctrl = KMALLOC(dtree_pcie_ctrl_t);
  ctrl->tree = tree;
  ctrl->ctrl = node;
  g_pcie.ctrl_data = ctrl;
  g_pcie.translate_irq = &dtree_translate_irq;

  result = parse_ranges(node, &g_pcie.mmap);
  if (result) {
    return result;
  }

  result = parse_bus_range(node, &g_pcie);
  if (result) {
    return result;
  }

  return 0;
}
