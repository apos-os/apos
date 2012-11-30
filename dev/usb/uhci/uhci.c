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
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "dev/irq.h"
#include "dev/pci/pci-driver.h"
#include "dev/pci/pci.h"
#include "dev/usb/bus.h"
#include "dev/usb/hcd.h"
#include "dev/usb/request.h"
#include "dev/usb/uhci/uhci-internal.h"
#include "dev/usb/uhci/uhci.h"
#include "dev/usb/uhci/uhci_registers.h"
#include "dev/usb/usb_driver.h"
#include "kmalloc.h"
#include "page_alloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "slab_alloc.h"

// TODO(aoates): we don't need a table of UHCIs, since we can just store the
// data in the HCDI we give to the USBD.
#define UHCI_MAX_CONTROLLERS 10
static usb_uhci_t g_controllers[UHCI_MAX_CONTROLLERS];
static int g_num_controllers = 0;

// Slab allocators for QHs and TDs, and pending IRPs.
static slab_alloc_t* td_alloc = 0x0;
static slab_alloc_t* qh_alloc = 0x0;
static slab_alloc_t* pirp_alloc = 0x0;

// Maximum number of pages to allocate in TD and QH slab allocators.
#define SLAB_MAX_PAGES 10

static inline uhci_qh_t* alloc_qh() {
  return (uhci_qh_t*)slab_alloc(qh_alloc);
}

static inline uhci_td_t* alloc_td() {
  return (uhci_td_t*)slab_alloc(td_alloc);
}

static inline uhci_pending_irp_t* alloc_pending_irp() {
  return (uhci_pending_irp_t*)slab_alloc(pirp_alloc);
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
  KASSERT(irp->endpoint->device->speed == USB_LOW_SPEED ||
          irp->endpoint->device->speed == USB_FULL_SPEED);
  KASSERT(irp->endpoint->endpoint_idx < USB_NUM_ENDPOINTS);
  KASSERT(irp->endpoint->device->endpoints[irp->endpoint->endpoint_idx] ==
          irp->endpoint);

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

  // If the transfer is bound for the root hub, intercept it.
  // TODO(aoates): we don't currently track that intercepted IRPs are
  // one-at-a-time (unlike normal IRPs), so multiple simultaneous ones could
  // wreak havoc.
  if (irp->endpoint->device->address == uhci_hc->root_hub->address) {
    return uhci_hub_handle_irp(uhci_hc->root_hub, irp);
  }

  // Create a sequence of TDs for the transfer.
  uint32_t bytes_left = irp->buflen;
  uhci_td_t* prev = 0x0;
  uhci_td_t* ctd = 0x0;
  uhci_td_t* head_td = 0x0;
  uint32_t buf_phys = irp->buffer == 0x0 ? 0 : virt2phys((uint32_t)irp->buffer);
  // Create at least 1 TD (even if the data length is 0).
  do {
    ctd = alloc_td();
    if (!head_td) {
      head_td = ctd;
    }
    // Fill in the current TD.
    const uint16_t packet_len = min(bytes_left, irp->endpoint->max_packet);
    kmemset(ctd, 0, sizeof(uhci_td_t));

    ctd->link_ptr = TD_LINK_PTR_TERM;
    // TODO(aoates): probably want SPD as well.
    if (irp->endpoint->device->speed == USB_LOW_SPEED) {
      ctd->status_ctrl = TD_SC_LS;
    } else {
      ctd->status_ctrl = 0x0;
    }
    ctd->status_ctrl |= TD_SC_STS_ACTIVE;
    KASSERT(packet_len < 1280);
    const uint16_t td_max_len = packet_len > 0 ? packet_len - 1 : 0x7FF;
    ctd->token =
      ((td_max_len << TD_TOK_MAXLEN_OFFSET) & TD_TOK_MAXLEN_MASK) |
      ((irp->endpoint->endpoint_idx << TD_TOK_ENDPT_OFFSET) & TD_TOK_ENDPT_MASK) |
      ((irp->endpoint->device->address << TD_TOK_DADDR_OFFSET) & TD_TOK_DADDR_MASK) |
      (irp->pid & TD_TOK_PID_MASK);

    // Toggle the data toggle bit.
    if (irp->endpoint->data_toggle == USB_DATA1) {
      ctd->token |= TD_TOK_DATA1;
      irp->endpoint->data_toggle = USB_DATA0;
    } else {
      irp->endpoint->data_toggle = USB_DATA1;
    }
    ctd->buf_ptr = buf_phys;

    ctd->data[TD_DATA_BUF_OFFSET] = (irp->buflen - bytes_left);

    buf_phys += packet_len;
    bytes_left -= packet_len;

    // Connect the previous TD to this one.
    if (prev) {
      prev->link_ptr =
        (virt2phys((uint32_t)ctd) & TD_LINK_PTR_ADDR_MASK);
    }
    prev = ctd;
  } while (bytes_left > 0);
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

  // Add it to the pending IRP list.
  uhci_pending_irp_t* pirp = alloc_pending_irp();
  pirp->next = uhci_hc->pending_irps;
  pirp->qh = transfer_qh;
  pirp->td = ctd;
  uhci_hc->pending_irps = irp;

  irp->hcd_data = pirp;
  irp->endpoint->hcd_data = transfer_qh;
  irp->status = USB_IRP_PENDING;

  // TODO(aoates):
  //  On transfer finish:
  //   1) find the transfer QH
  //   2) remove it from the endpoint QH
  //   3) clean up memory, invoke callback

  POP_INTERRUPTS();
  return 0;
}

static void uhci_interrupt(void* arg) {
  usb_uhci_t* c = (usb_uhci_t*)arg;
  uint16_t status = ins(c->base_port + USBSTS);
  // TODO(aoates): handle halted condition, host errors, etc.
  KASSERT((status & 0xFFFC) == 0);

  // TODO(aoates): handle short packet detect!
  // Find the transaction that finished.
  usb_hcdi_irp_t* prev = 0x0;
  usb_hcdi_irp_t* irp = c->pending_irps;
  while (irp) {
    uhci_pending_irp_t* pirp = (uhci_pending_irp_t*)irp->hcd_data;
    int done = 0;
    uhci_td_t* final_td = 0x0;

    // Check if we got through the entire queue.
    if (pirp->qh->elt_link_ptr & QH_TERM) {
      done = 1;
      final_td = pirp->td;
    } else {
      // Otherwise check if the first TD in the queue is inactive (indicating a
      // short packet or an error).
      KASSERT(!(pirp->qh->elt_link_ptr & QH_QH));
      uhci_td_t* head_td = (uhci_td_t*)
          phys2virt(pirp->qh->elt_link_ptr & QH_LINK_PTR_MASK);
      if ((head_td->status_ctrl & TD_SC_STS_ACTIVE) == 0) {
        done = 1;
        final_td = head_td;
      }
    }

    if (done) {
      // The final TD must have been retired.
      KASSERT((final_td->status_ctrl & TD_SC_STS_ACTIVE) == 0);

      if (final_td->status_ctrl & TD_SC_STS_STALLED) {
        irp->status = USB_IRP_STALL;
      } else if (final_td->status_ctrl & TD_SC_STS_DBUF_ERR ||
                 final_td->status_ctrl & TD_SC_STS_BABBLE ||
                 final_td->status_ctrl & TD_SC_STS_TOCRC_ERR ||
                 final_td->status_ctrl & TD_SC_STS_BITSF_ERR) {
        klogf("WARNING: UHCI TD failed\n");
        irp->status = USB_IRP_DEVICE_ERROR;
      } else {
        irp->status = USB_IRP_SUCCESS;
      }

      const uint16_t td_act_len = final_td->status_ctrl & TD_SC_ACTLEN_MASK;
      const uint16_t act_len = td_act_len != 0x7FF ? td_act_len + 1 : 0;
      irp->out_len = final_td->data[TD_DATA_BUF_OFFSET] + act_len;

      // Unlink it from the pending IRP list.
      if (prev) {
        ((uhci_pending_irp_t*)prev->hcd_data)->next = pirp->next;
      } else {
        c->pending_irps = pirp->next;
      }
      pirp->next = 0x0;  // Just in case.

      // Mark the endpoint as free.
      irp->endpoint->hcd_data = 0x0;

      // Remove the QH from the type queue.
      // TODO

      // Invoke the callback.
      if (irp->callback) {
        irp->callback(irp, irp->callback_arg);
      }
    }

    irp = pirp->next;
  }

  // Clear the txn error and IOC bits.
  outs(c->base_port + USBSTS, 0x3);
}

static void init_controller(usb_uhci_t* c) {
  if (!td_alloc) {
    td_alloc = slab_alloc_create(sizeof(uhci_td_t), SLAB_MAX_PAGES);
  }
  if (!qh_alloc) {
    qh_alloc = slab_alloc_create(sizeof(uhci_td_t), SLAB_MAX_PAGES);
  }
  if (!pirp_alloc) {
    pirp_alloc = slab_alloc_create(sizeof(uhci_pending_irp_t), SLAB_MAX_PAGES);
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
  outs(c->base_port + USBINTR, USBINTR_IOC | USBINTR_TMO_CRC);

  c->pending_irps = 0x0;

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

  // Initialize the root hub controller.
  KASSERT(0 == uhci_hub_init(c));

  // Start the controller.
  uint16_t cmd = ins(c->base_port + USBCMD);
  cmd |= USBCMD_CF | USBCMD_RS;
  outs(c->base_port + USBCMD, cmd);
}

// Test sequence for the controller that detects devices and sends their
// descriptors.
void uhci_test_controller(usb_hcdi_t* ci, int port) {
  void irp_callback(usb_irp_t* irp, void* arg) {
    int* done = (int*)arg;
    *done = 1;
  }
  if (port < 0 || port > 1) {
    klogf("error: port %d out of range\n", port);
    return;
  }

  usb_uhci_t* c = (usb_uhci_t*)ci->dev_data;
  const uint16_t port_reg = c->base_port +
      (port == 0 ? PORTSC1 : PORTSC2);

  uint16_t status = ins(port_reg);
  if (!(status & PORTSC_CONNECT)) {
    klogf("<no device found on port %d>\n", port + 1);
    return;
  }

  // Reset change bit.
  outs(port_reg, PORTSC_CONNECT_CHG);

  // Reset the port.
  klogf("resetting port %d\n", port + 1);
  status = ins(port_reg);
  outs(port_reg, status | PORTSC_RST);
  ksleep(100);

  status = ins(port_reg);
  outs(port_reg, status & ~PORTSC_RST);

  // Enable the port.
  klogf("enabling port %d\n", port + 1);
  status = ins(port_reg);
  outs(port_reg, status | PORTSC_ENABLE | PORTSC_ENABLE_CHG);
  ksleep(100);

  // Make a fake bus and device.
  usb_bus_t* bus = (usb_bus_t*)kmalloc(sizeof(usb_bus_t));;
  kmemset(bus, 0, sizeof(usb_bus_t));
  bus->hcd = ci;
  bus->next_address = 1;

  usb_device_t* device = usb_create_device(
      bus, 0x0, (status & PORTSC_LOSPEED) ? USB_LOW_SPEED : USB_FULL_SPEED);
  device->state = USB_DEV_DEFAULT;
  usb_init_device(device);
}

void usb_uhci_register_controller(uint32_t base_addr, uint8_t irq) {
  if (g_num_controllers >= UHCI_MAX_CONTROLLERS) {
    klogf("WARNING: too many UHCI controllers; ignoring\n");
    return;
  }
  if (irq == 0xFF) {
    klogf("WARNING: UHCI controllers without IRQs are unsupported\n");
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

  // Register IRQ handler for the controller.
  // TODO(aoates): this will clobber any other controllers listening on this
  // IRQ!  This is probably not what we want.
  klogf("registering UHCI at base port 0x%x on IRQ %d\n", base_addr, (uint32_t)irq);
  register_irq_handler(irq, &uhci_interrupt, c);

  // Register it with the USBD.
  usb_hcdi_t* hcdi = (usb_hcdi_t*)kmalloc(sizeof(usb_hcdi_t));
  kmemset(hcdi, 0, sizeof(usb_hcdi_t));
  hcdi->register_endpoint = &uhci_register_endpoint;
  hcdi->unregister_endpoint = &uhci_unregister_endpoint;
  hcdi->schedule_irp = &uhci_schedule_irp;
  hcdi->dev_data = c;
  usb_create_bus(hcdi);
}

void usb_uhci_interrupt(int handle) {
  KASSERT(handle >= 0 && handle < g_num_controllers);
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
