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

#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/usb/uhci/uhci.h"
#include "page_alloc.h"

// UHCI I/O Registers (offsets from the base).
#define USBCMD     0x00  // 16 bits
#define USBSTS     0x02  // 16 bits
#define USBINTR    0x04  // 16 bits
#define FRNUM      0x06  // 16 bits
#define FLBASEADDR 0x08  // 32 bits
#define SOF_MODIFY 0x0C  // 8 bits
#define PORTSC1    0x10  // 16 bits
#define PORTSC2    0x12  // 16 bits

// Bits within those registers.
#define USBCMD_MAXP    0x0080  // Max packet (1=64 bytes, 0=32 bytes)
#define USBCMD_CF      0x0040  // Configure flag (set by software)
#define USBCMD_SWDBG   0x0020  // Software debug
#define USBCMD_FGR     0x0010  // Force global resume
#define USBCMD_EGSM    0x0008  // Enter global suspend mode
#define USBCMD_GRESET  0x0004  // Global reset
#define USBCMD_HCRESET 0x0002  // Host controller reset
#define USBCMD_RS      0x0001  // Run/stop

#define USBSTS_HALTED     0x0020  // Host controller halted
#define USBSTS_HCERROR    0x0010  // Host controller process error
#define USBSTS_HSYSERROR  0x0008  // Host system (e.g. PCI) error
#define USBSTS_RESUME     0x0004  // Resume detect
#define USBSTS_ERRINT     0x0002  // USB error interrupt
#define USBSTS_INT        0x0001  // USB interrupt (IOC, SPD, etc)

#define USBINTR_SHORTP    0x0008  // Short packet interrupt enable
#define USBINTR_IOC       0x0004  // Interrupt on complete interrupt enable
#define USBINTR_RESUME    0x0002  // Resume interrupt enable
#define USBINTR_TMO_CRC   0x0001  // Timeout/CRC interrupt enable

#define FRNUM_MASK  0x07FF  // Only bits 10:0 are used for the frnum
#define FLBASEADDR_MASK 0xFFFFF000  // Must be page-aligned

// Port status/control bits.  One set each for port1 and port2.
#define PORTSC_SUSPEND     0x1000  // R/W (1=suspended)
#define PORTSC_RST         0x0200  // R/W - Port reset
#define PORTSC_LOSPEED     0x0100  // R/O - Low speed device attached
#define PORTSC_RESUME_DTCT 0x0040  // R/W - Resume detect enable
#define PORTSC_LINE_STATUS 0x0030  // R/O - Line status bits
#define PORTSC_ENABLE_CHG  0x0008  // R/WC - Enable/disable status change
#define PORTSC_ENABLE      0x0004  // R/W - Enable/disable port
#define PORTSC_CONNECT_CHG 0x0002  // R/WC - Connect status change
#define PORTSC_CONNECT     0x0001  // R/O - Connect status (1=device connected)

#define UHCI_MAX_CONTROLLERS 10
static usb_uhci_t g_controllers[UHCI_MAX_CONTROLLERS];
static int g_num_controllers = 0;

static void init_controller(usb_uhci_t* c) {
  uint32_t frame_list_phys = page_frame_alloc();
  c->frame_list = (uint32_t*)phys2virt(frame_list_phys);

  // TODO(aoates): do a global reset on the bus.

  // Set max packet to 64 bytes and disable everything.
  outs(c->base_port + USBCMD, USBCMD_MAXP);

  // Set the frame list address and frame number registers.
  KASSERT((frame_list_phys & FLBASEADDR_MASK) == frame_list_phys);
  outl(c->base_port + FLBASEADDR, frame_list_phys);
  outs(c->base_port + FRNUM, 0x00);
}

void usb_uhci_register_controller(uint32_t base_addr) {
  if (g_num_controllers >= UHCI_MAX_CONTROLLERS) {
    klogf("WARNING: too many UHCI controllers; ignoring\n");
    return;
  }
  usb_uhci_t* c = &g_controllers[g_num_controllers++];
  kmemset(c, 0, sizeof(usb_uhci_t));
  c->base_port = base_addr;
  klogf("USB: found UHCI controller #%d (at 0x%x)\n", g_num_controllers,
        c->base_port);

  // Initialize the controller.
  // TODO(aoates): we probably need to mask interrupts.
  init_controller(c);
}

int usb_uhci_num_controllers() {
  return g_num_controllers;
}

usb_uhci_t* usb_uhci_get_controller(int i) {
  if (i < 0 || i >= g_num_controllers) {
    return 0x0;
  }
  return &g_controllers[i];
}
