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

#include "arch/common/endian.h"
#include "arch/common/io.h"
#include "arch/dev/irq.h"
#include "arch/memory/page_alloc.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "dev/pci/pci-driver.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

typedef struct {
  nic_t public;     // Public NIC fields
  uint32_t iobase;  // Base IO register address
  uint16_t rxstart;
  void* rxbuf;
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

// Bits in the command register.
typedef enum {
  RTL_CMD_BUFE = 1 << 0,       // Buffer Empty (BUFE)
  RTL_CMD_TX_ENABLE = 1 << 2,  // Transmitter Enable (TE)
  RTL_CMD_RX_ENABLE = 1 << 3,  // Receiver Enable (RE)
  RTL_CMD_RST = 1 << 4,        // Reset (RST)
} rtl_cmd_reg_bits_t;

// Bits in the interrupt mask register.
typedef enum {
  RTL_IMR_ROK = 1 << 0,  // Receive OK
  RTL_IMR_TOK = 1 << 2,  // Transmit OK
} rtl_imr_reg_bits_t;

// Bits in the receive config register.
typedef enum {
  RTL_RCR_AAP = 1 << 0,   // Accept all packets (promiscous mode)
  RTL_RCR_APM = 1 << 1,   // Accept physical match packets
  RTL_RCR_AM = 1 << 2,    // Accept multicast packets
  RTL_RCR_AB = 1 << 3,    // Accept broadcast packets
  RTL_RCR_WRAP = 1 << 7,  // Wrap bit (disables wrapping large packets)
} rtl_rcr_reg_bits_t;

#define RTL_RXBUF_SIZE 8192
#define RTL_RX_PACKET_HDR_SIZE 4

// Bits in the received packet header set by the NIC.
typedef enum {
  RTL_RXHDR_ROK = 1 << 0,   // Receive OK
  RTL_RXHDR_BAR = 1 << 13,  // Broadcast address received
  RTL_RXHDR_PAM = 1 << 14,  // Physical address matched
  RTL_RXHDR_MAR = 1 << 15,  // Multicast address recieved
} rtl_rx_header_bits_t;

static void rtl_handle_recv_one(rtl8139_t* nic) {
  // Read the packet header.
  uint32_t header;
  kmemcpy(&header, nic->rxbuf + nic->rxstart, RTL_RX_PACKET_HDR_SIZE);
  header = ltoh32(header);
  KLOG(DEBUG2, "packet header: %#x\n", header);
  const uint16_t rx_status = header & 0xFFFF;
  const uint16_t plen = header >> 16;
  // TODO(aoates): sanity check that the packet isn't longer than the end
  // pointer.
  if (rx_status & RTL_RXHDR_ROK) {
    KLOG(DEBUG2, "received packet len=%d\n", plen);
    // TODO(aoates): actually, you know, handle the packet.
  } else {
    // TODO(aoates): increment stats.
    KLOG(DEBUG, "received bad packet (status: %#x, len: %d)\n",
         rx_status, plen);
  }

  // Release the buffer space to the NIC.
  nic->rxstart += plen + RTL_RX_PACKET_HDR_SIZE;
  nic->rxstart %= RTL_RXBUF_SIZE;
  // N.B.(aoates): it's unclear why we need to offset this by 0x10, but qemu has
  // the reverse transformation in its emulated NIC, and other drivers seem to
  // do this as well.  God forbid the RTL8139 datasheet actually be useful and
  // document this...
  outs(nic->iobase + RTLRG_RXBUF_START, nic->rxstart - 0x10);
}

static void rtl_handle_recv(rtl8139_t* nic) {
  int packets = 0;
  uint16_t rxbuf_end = ltoh16(ins(nic->iobase + RTLRG_RXBUF_END));
  while (rxbuf_end != nic->rxstart) {
    // TODO(aoates): increment stats?
    packets++;
    KLOG(DEBUG2, "recv(%s): start=%#x end=%#x\n", nic->public.name,
         nic->rxstart, rxbuf_end);
    if (rxbuf_end - nic->rxstart < RTL_RX_PACKET_HDR_SIZE) {
      KLOG(INFO, "recv(%s): data in buffer too small!\n", nic->public.name);
      break;
    }
    rtl_handle_recv_one(nic);
    rxbuf_end = ltoh16(ins(nic->iobase + RTLRG_RXBUF_END));
  }
  KLOG(DEBUG2, "recv(%s): read %d packets\n", nic->public.name, packets);
}

static void rtl_irq_handler(void* arg) {
  rtl8139_t* nic = (rtl8139_t*)arg;
  const uint16_t interrupts = ins(nic->iobase + RTLRG_INTSTATUS);
  if (!interrupts) {
    // Spurious interrupt, ignore.
    return;
  }
  KLOG(DEBUG2, "IRQ received for %s: %#x\n", nic->public.name, interrupts);

  // Clear interrupt bits.  The data sheet says this shouldn't be
  // necessary....but qemu disagrees.
  outs(nic->iobase + RTLRG_INTSTATUS, interrupts);

  // TODO(aoates): we should _not_ be doing this in an interrupt context.
  if (interrupts & RTL_IMR_ROK) {
    rtl_handle_recv(nic);
  }
  // TODO(aoates): handle other interrupts (in particular, error cases).
}

static void rtl_init(pci_device_t* pcidev, rtl8139_t* nic) {
  // N.B.(aoates): some sources say we need to do some fiddling with the
  // power management bits (LWACT and LWPTN).  Doesn't seem to matter for qemu,
  // but haven't tried on real hardware.
  KLOG(DEBUG, "Enabling PCI bus mastering\n");
  pci_read_status(pcidev);  // Redundant, but let's be careful.
  pcidev->command |= PCI_CMD_BUSMASTER_ENABLE;
  pci_write_status(pcidev);

  // Start a reset, and disable RX and TX just in case.
  KLOG(DEBUG, "Resetting the NIC\n");
  outb(nic->iobase + RTLRG_CMD, RTL_CMD_RST);
  // Poll until the reset is done.
  // TODO(aoates): if this is slow, make it async so we don't block the full
  // system initialization on it.
  while (inb(nic->iobase + RTLRG_CMD) & RTL_CMD_RST) {
    // Do nothing.
  }

  // Allocate and initialize the receive buffer.
  // N.B.(aoates): AFAICT there's no alignment required by the RTL8139
  // spec....but page-align it to be safe.
  // TODO(aoates): this (and other buffers) should be constrained to the lower
  // 32-bits of the physical address space.
  KLOG(DEBUG, "Setting up receive buffer\n");
  phys_addr_t phys_rxbuf = page_frame_dma_alloc(3);  // 8k + 16
  nic->rxbuf = (void*)phys2virt(phys_rxbuf);
  nic->rxstart = 0;
  // TODO(aoates): find a better way for this kind of check and constraint.
  KASSERT(phys_rxbuf < UINT32_MAX);
  outl(nic->iobase + RTLRG_RBSTART, htol32((uint32_t)phys_rxbuf));

  // Set interrupt mask (rx and tx aren't enabled yet).
  // TODO(aoates): enable other interrupts (errors, in particular).
  outs(nic->iobase + RTLRG_INTMASK, RTL_IMR_ROK);

  // Set reasonable default receive config.  Receive some packets, non-wrap
  // mode, 8k+16 recv buffer size.
  outl(nic->iobase + RTLRG_RXCFG,
       RTL_RCR_AB | RTL_RCR_AM | RTL_RCR_APM | RTL_RCR_WRAP);

  // TODO(aoates): better way of asserting this is valid.
  KASSERT(pcidev->interrupt_line <= IRQ15);
  register_irq_handler(pcidev->interrupt_line, &rtl_irq_handler, nic);

  // Enable receiving.
  KLOG(DEBUG, "Enabling packet receiver\n");
  outb(nic->iobase + RTLRG_CMD, RTL_CMD_RX_ENABLE);
}

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
  rtl_init(pcidev, nic);
}
