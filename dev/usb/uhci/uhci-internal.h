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

#ifndef APOO_DEV_USB_UHCI_INTERNAL_H
#define APOO_DEV_USB_UHCI_INTERNAL_H

#include <stdint.h>

#include "dev/usb/hcd.h"
#include "dev/usb/uhci/uhci_hub.h"

// Bits in a frame list entry.
#define FL_PTR_MASK 0xFFFFFFF0
#define FL_PTR_QH   0x00000002
#define FL_PTR_TERM 0x00000001

// A UHCI transfer descriptor (TD).
#define TD_LINK_PTR_ADDR_MASK  0xFFFFFFF0
#define TD_LINK_PTR_VF 0x04     // 1 = depth first, 0 = breadth-first
#define TD_LINK_PTR_QH 0x02     // Link ptr type.  1 = QH, 0 = TD
#define TD_LINK_PTR_TERM 0x01   // Terminate (1 = last entry)

// Bits in the status_ctrl field.
#define TD_SC_SPD            0x20000000  // Short packet detect
#define TD_SC_ERR_MASK       0x18000000  // Error countdown
#define TD_SC_ERR_OFFSET     24          // Error countdown offset
#define TD_SC_LS             0x04000000  // Low-speed device
#define TD_SC_IOS            0x02000000  // Isochronous select
#define TD_SC_IOC            0x01000000  // Interrupt-on-complete
#define TD_SC_STS_ACTIVE     0x00800000  // Active
#define TD_SC_STS_STALLED    0x00400000  // Stalled
#define TD_SC_STS_DBUF_ERR   0x00200000  // Data buffer error
#define TD_SC_STS_BABBLE     0x00100000  // Babble detected
#define TD_SC_STS_NAK        0x00080000  // NAK receieved
#define TD_SC_STS_TOCRC_ERR  0x00040000  // Timeout/CRC error
#define TD_SC_STS_BITSF_ERR  0x00020000  // Bitstuff error
#define TD_SC_ACTLEN_MASK    0x000007FF  // Actual length transmitted

// Bits and masks in the token field.
#define TD_TOK_MAXLEN_MASK   0xFFE00000  // Max length (up to 0x3FF; see spec)
#define TD_TOK_MAXLEN_OFFSET 21
#define TD_TOK_DATA1         0x00080000  // Data toggle bits (DATA0 or DATA1),
#define TD_TOK_DATA0         0x00000000  // for the 1-bit sequence number
#define TD_TOK_ENDPT_MASK    0x00078000  // Endpoint number
#define TD_TOK_ENDPT_OFFSET  15
#define TD_TOK_DADDR_MASK    0x00007F00  // Device address
#define TD_TOK_DADDR_OFFSET  8
#define TD_TOK_PID_MASK      0x000000FF

// The different fields of the TD custom data section.
// This is the offset into the buffer of this TD (that is, the number of bytes
// represented by all the TDS in the transfer before this one).
#define TD_DATA_BUF_OFFSET 0

struct uhci_td {
  uint32_t link_ptr;  // Link pointer and associated flags.
  uint32_t status_ctrl;  // Status and control bits.
  uint32_t token;  // Information about the transaction.
  uint32_t buf_ptr;  // Buffer pointer.
  uint32_t data[4];  // Data we can use.
};
typedef struct uhci_td uhci_td_t;

// A queue head.  These bits and masks apply to both head and element pointers
// in the QH struct.
#define QH_LINK_PTR_MASK 0xFFFFFFF0  // Mask for the pointer value
#define QH_QH            0x00000002  // Type of link.  1=QH, 0=TD
#define QH_TERM          0x00000001  // Terminal element

struct uhci_qh {
  uint32_t head_link_ptr;  // Horizontal link, and flags.
  uint32_t elt_link_ptr;   // Vertical link, and flags.
};
typedef struct uhci_qh uhci_qh_t;

// A pending IRP.  Pointed to by the hcd_data field of a usb_hcdi_irp_t struct.
struct uhci_pending_irp {
  usb_hcdi_irp_t* next;  // Next IRP in the pending list.
  uhci_qh_t* qh;  // The QH for this transfer.
  // The final TD for the transfer (used as a shortcut for finding IOC TDs).
  uhci_td_t* td;
};
typedef struct uhci_pending_irp uhci_pending_irp_t;

struct usb_uhci {
  uint32_t base_port;  // USBBASE register.
  int irq;
  uint32_t* frame_list;  // Pointer to the frame list.

  // Queue heads for the three queues of transfers.
  uhci_qh_t* interrupt_qh;
  uhci_qh_t* control_qh;
  uhci_qh_t* bulk_qh;

  // Linked-list of pending IRPs.
  usb_hcdi_irp_t* pending_irps;

  // Fake controller for the root hub.
  uhci_hub_t* root_hub;
};

// HACK
// Run some tests on the controller.  Leaves it in an inconsistent state, and
// should not be run outside of debugging.
void uhci_test_controller(usb_hcdi_t* ci, int port);

#endif
