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

#include "common/errno.h"
#include "common/io.h"
#include "common/math.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci.h"
#include "dev/usb/hcd.h"
#include "dev/usb/request.h"
#include "dev/usb/uhci/uhci-internal.h"
#include "dev/usb/uhci/uhci.h"
#include "page_alloc.h"
#include "slab_alloc.h"

// Number of frames in the frame list.
#define UHCI_NUM_FRAMES 1024

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

// TODO(aoates): we don't need a table of UHCIs, since we can just store the
// data in the HCDI we give to the USBD.
#define UHCI_MAX_CONTROLLERS 10
static usb_uhci_t g_controllers[UHCI_MAX_CONTROLLERS];
static int g_num_controllers = 0;

// Slab allocators for QHs and TDs.
static slab_alloc_t* td_alloc = 0x0;
static slab_alloc_t* qh_alloc = 0x0;

// Maximum number of pages to allocate in TD and QH slab allocators.
#define SLAB_MAX_PAGES 10

static inline uhci_qh_t* alloc_qh() {
  return (uhci_qh_t*)slab_alloc(qh_alloc);
}

static inline uhci_td_t* alloc_td() {
  return (uhci_td_t*)slab_alloc(td_alloc);
}

static int uhci_register_endpoint(struct usb_hcdi* hc, usb_endpoint_t* ep) {
  ep->hcd_data = 0x0;
  return 0;
}

static int uhci_unregister_endpoint(struct usb_hcdi* hc, usb_endpoint_t* ep) {
  return 0;
}

// The schedule_irp function in the UHCI HCDI.
//
// Note: we don't really do anything fancy, and this isn't completely compliant.
// For example, we take no pains to ensure that bus time is allocated
// appropriately to the different transfer types.
static int uhci_schedule_irp(struct usb_hcdi* hc, usb_hcdi_irp_t* irp) {
  usb_uhci_t* uhci_hc = (usb_uhci_t*)hc->dev_data;
  if (irp->endpoint->type == USB_ISOCHRONOUS) {
    return -ENOTSUP;
  }
  if (uhci_hc == 0x0) {
    return -EINVAL;
  }
  KASSERT(irp->endpoint->max_packet <= 64);
  KASSERT(irp->endpoint->speed == USB_LOW_SPEED ||
          irp->endpoint->speed == USB_FULL_SPEED);

  PUSH_AND_DISABLE_INTERRUPTS();
  if (irp->endpoint->hcd_data != 0x0) {
    POP_INTERRUPTS();
    klogf("WARNING: UHCI scheduling IRP on busy endpoint\n");
    return -EBUSY;
  }

  // If requested, reset the endpoint's data toggle.
  switch (irp->data_toggle) {
    case USB_DATA_TOGGLE_NORMAL: break;
    case USB_DATA_TOGGLE_RESET0: irp->endpoint->data_toggle = USB_DATA0; break;
    case USB_DATA_TOGGLE_RESET1: irp->endpoint->data_toggle = USB_DATA1; break;
  }

  // Create a sequence of TDs for the transfer.
  uint32_t bytes_left = irp->buflen;
  uhci_td_t* prev = 0x0;
  uhci_td_t* ctd = alloc_td();
  uhci_td_t* head_td = ctd;
  uint32_t buf_phys = virt2phys((uint32_t)irp->buffer);
  while (bytes_left > 0) {
    // Fill in the current TD.
    const uint16_t packet_len = min(bytes_left, irp->endpoint->max_packet);
    kmemset(ctd, 0, sizeof(uhci_td_t));

    ctd->link_ptr = TD_LINK_PTR_TERM;
    // TODO(aoates): probably want SPD as well.
    if (irp->endpoint->speed == USB_LOW_SPEED) {
      ctd->status_ctrl = TD_SC_LS;
    } else {
      ctd->status_ctrl = 0x0;
    }
    KASSERT(packet_len < 1280);
    const uint16_t td_max_len = packet_len > 0 ? packet_len - 1 : 0x7FF;
    ctd->token =
      ((td_max_len << TD_TOK_MAXLEN_OFFSET) & TD_TOK_MAXLEN_MASK) |
      ((irp->endpoint->endpoint << TD_TOK_ENDPT_OFFSET) & TD_TOK_ENDPT_MASK) |
      ((irp->endpoint->address << TD_TOK_DADDR_OFFSET) & TD_TOK_DADDR_MASK) |
      (irp->pid & TD_TOK_PID_MASK);

    // Toggle the data toggle bit.
    if (irp->endpoint->data_toggle == USB_DATA1) {
      ctd->token |= TD_TOK_DATA1;
      irp->endpoint->data_toggle = USB_DATA0;
    } else {
      irp->endpoint->data_toggle = USB_DATA1;
    }
    ctd->buf_ptr = buf_phys;
    buf_phys += packet_len;
    bytes_left -= packet_len;

    // Connect the previous TD to this one.
    if (prev) {
      prev->link_ptr =
        (virt2phys((uint32_t)ctd) & TD_LINK_PTR_ADDR_MASK);
    }
    prev = ctd;
  }
  ctd->status_ctrl |= TD_SC_IOC;

  // Create a QH for the transfer.
  uhci_qh_t* transfer_qh = alloc_qh();
  KASSERT(((uint32_t)head_td & QH_LINK_PTR_MASK) == (uint32_t)head_td);
  transfer_qh->elt_link_ptr = virt2phys((uint32_t)head_td);  // Non-terminal TD.
  transfer_qh->head_link_ptr = 0x0;

  // Insert it into the appropriate queue.
  uhci_qh_t* type_qh = 0x0;
  uint32_t next_type_qh = 0x0;
  switch (irp->endpoint->type) {
    case USB_INTERRUPT:
      type_qh = uhci_hc->interrupt_qh;
      next_type_qh = virt2phys((uint32_t)uhci_hc->control_qh) | QH_QH;
      break;
    case USB_CONTROL:
      type_qh = uhci_hc->control_qh;
      next_type_qh = virt2phys((uint32_t)uhci_hc->bulk_qh) | QH_QH;
      break;
    case USB_BULK:
      type_qh = uhci_hc->bulk_qh;
      next_type_qh = QH_QH | QH_TERM;
      break;
    default:
      KASSERT(0);
  }

  // The HC doesn't modify the QHs if they point to other QHs, so we're safe
  // from concurrent accesses.
  if (type_qh->elt_link_ptr & QH_TERM) {
    transfer_qh->head_link_ptr = next_type_qh;
  } else {
    KASSERT(type_qh->elt_link_ptr & QH_QH);
    transfer_qh->head_link_ptr = type_qh->elt_link_ptr | QH_QH;
  }
  type_qh->elt_link_ptr = virt2phys((uint32_t)transfer_qh) | QH_QH;

  irp->endpoint->hcd_data = transfer_qh;

  // TODO(aoates):
  //  On transfer finish:
  //   1) find the transfer QH
  //   2) remove it from the endpoint QH
  //   3) clean up memory, invoke callback

  POP_INTERRUPTS();
  return 0;
}

static void init_controller(usb_uhci_t* c) {
  if (!td_alloc) {
    td_alloc = slab_alloc_create(sizeof(uhci_td_t), SLAB_MAX_PAGES);
  }
  if (!qh_alloc) {
    qh_alloc = slab_alloc_create(sizeof(uhci_td_t), SLAB_MAX_PAGES);
  }

  uint32_t frame_list_phys = page_frame_alloc();
  c->frame_list = (uint32_t*)phys2virt(frame_list_phys);

  // TODO(aoates): do a global reset on the bus.

  // Set max packet to 64 bytes and disable everything.
  outs(c->base_port + USBCMD, USBCMD_MAXP);

  // Set the frame list address and frame number registers.
  KASSERT((frame_list_phys & FLBASEADDR_MASK) == frame_list_phys);
  outl(c->base_port + FLBASEADDR, frame_list_phys);
  outs(c->base_port + FRNUM, 0x00);

  // Create a QH for each type of transfer we support.
  c->interrupt_qh = alloc_qh();
  c->control_qh = alloc_qh();
  c->bulk_qh = alloc_qh();
  kmemset(c->interrupt_qh, 0, sizeof(uhci_qh_t));
  kmemset(c->control_qh, 0, sizeof(uhci_qh_t));
  kmemset(c->bulk_qh, 0, sizeof(uhci_qh_t));

  // Link them to each other horizontally, and mark their vertical links as
  // terminal.
  KASSERT(((uint32_t)c->interrupt_qh & QH_LINK_PTR_MASK) == (uint32_t)c->interrupt_qh);
  KASSERT(((uint32_t)c->control_qh & QH_LINK_PTR_MASK) == (uint32_t)c->control_qh);
  KASSERT(((uint32_t)c->bulk_qh & QH_LINK_PTR_MASK) == (uint32_t)c->bulk_qh);

  c->interrupt_qh->head_link_ptr =
    (virt2phys((uint32_t)c->control_qh) & QH_LINK_PTR_MASK) | QH_QH;
  c->interrupt_qh->elt_link_ptr = QH_TERM;

  c->control_qh->head_link_ptr =
    (virt2phys((uint32_t)c->bulk_qh) & QH_LINK_PTR_MASK) | QH_QH;
  c->control_qh->elt_link_ptr = QH_TERM;

  // TODO(aoates): if we want to support bandwidth reclamation, we should loop
  // this back around.
  c->bulk_qh->head_link_ptr = QH_TERM;
  c->bulk_qh->elt_link_ptr = QH_TERM;

  // Make each element in the frame list point at our queues.
  const uint32_t frame_list_entry =
      virt2phys((uint32_t)c->interrupt_qh) | FL_PTR_QH;
  for (int i = 0; i < UHCI_NUM_FRAMES; ++i) {
    c->frame_list[i] = frame_list_entry;
  }

  // Start the controller.
  uint16_t cmd = ins(c->base_port + USBCMD);
  cmd |= USBCMD_CF | USBCMD_RS;
  outs(c->base_port + USBCMD, cmd);
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

  // Register it with the USBD.
  usb_hcdi_t hcdi;
  kmemset(&hcdi, 0, sizeof(usb_hcdi_t));
  hcdi.register_endpoint = &uhci_register_endpoint;
  hcdi.unregister_endpoint = &uhci_unregister_endpoint;
  hcdi.schedule_irp = &uhci_schedule_irp;
  hcdi.dev_data = c;
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
