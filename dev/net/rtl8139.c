// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#include "arch/common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/net/nic.h"
#include "dev/pci/pci-driver.h"
#include "memory/kmalloc.h"

typedef struct {
  nic_t public;     // Public NIC fields
  uint32_t iobase;  // Base IO register address
} rtl8139_t;

// PCI configuration registers (all IO-space mapped).
typedef enum {
  RTLRG_IDR0 = 0x0000,         // ID register 0
  RTLRG_IDR1 = 0x0001,         // ID register 1
  RTLRG_IDR2 = 0x0002,         // ID register 2
  RTLRG_IDR3 = 0x0003,         // ID register 3
  RTLRG_IDR4 = 0x0004,         // ID register 4
  RTLRG_IDR5 = 0x0005,         // ID register 5
  RTLRG_RBSTART = 0x0030,      // Receive buffer start (physical addr)
  RTLRG_CMD = 0x0037,          // Command register
  RTLRG_RXBUF_START = 0x0038,  // Receive buffer start/how much is read (CAPR)
  RTLRG_RXBUF_END = 0x003a,    // Receive buffer end/how much is written (CBR)
  RTLRG_INTMASK = 0x003c,      // Interrupt mask register (IMR)
  RTLRG_INTSTATUS = 0x003e,    // Interrupt status register (ISR)
  RTLRG_RXCFG = 0x0044,        // Receive config register (RCR)
} rtl_io_regs_t;

void pci_rtl8139_init(pci_device_t* pcidev) {
  klogf("net: found RTL8139 NIC; initializing\n");
  // TODO(aoates): don't die if we get a bad device.
  KASSERT(pcidev->class_code == 0x02);     // Network controller
  KASSERT(pcidev->subclass_code == 0x00);  // Ethernet

  // We should have two BARs, one for IO-mapped and one for memory-mapped.
  KASSERT(pcidev->base_address[0] != 0);
  KASSERT((pcidev->base_address[0] & 0x1) == 1);
  KASSERT(pcidev->base_address[1] != 0);
  KASSERT((pcidev->base_address[1] & 0x1) == 0);

  rtl8139_t* nic = kmalloc(sizeof(rtl8139_t));
  nic->public.type = NIC_ETHERNET;
  nic->iobase = pcidev->base_address[0] & ~0x3;

  // Find the MAC address of the device.
  // N.B.(aoates): the RTL8139 datasheet is contradictory---it says that these
  // can only be accessed in 4-byte chunks...but then says the exact opposite
  // right after.
  nic->public.mac[0] = inb(nic->iobase + RTLRG_IDR0);
  nic->public.mac[1] = inb(nic->iobase + RTLRG_IDR1);
  nic->public.mac[2] = inb(nic->iobase + RTLRG_IDR2);
  nic->public.mac[3] = inb(nic->iobase + RTLRG_IDR3);
  nic->public.mac[4] = inb(nic->iobase + RTLRG_IDR4);
  nic->public.mac[5] = inb(nic->iobase + RTLRG_IDR5);

  nic_create(&nic->public, "eth");
}
