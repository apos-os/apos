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

#include "arch/dev/irq.h"
#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/io.h"
#include "dev/net/nic.h"
#include "dev/pci/pci-driver.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "net/eth/eth.h"
#include "proc/defint.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

static nic_ops_t rtl_ops;

#define RTL_NUM_TX_DESCS 4

#define DWORD_ALIGN(x) (((x) + 3) & ~0x3)

// TODO(aoates): lots of parts of this are touched in an interrupt context---go
// through and ensure the appropriate memory barriers are in place.
typedef struct {
  nic_t public;     // Public NIC fields
  devio_t io;
  uint16_t rxstart;
  void* rxbuf;
  int txdesc;
  void* txbuf[RTL_NUM_TX_DESCS];
  bool txbuf_active[RTL_NUM_TX_DESCS];
} rtl8139_t;

// PCI configuration registers (all IO-space mapped).
typedef enum {
  RTLRG_IDR0 = 0x0000,         // ID register 0
  RTLRG_IDR1 = 0x0001,         // ID register 1
  RTLRG_IDR2 = 0x0002,         // ID register 2
  RTLRG_IDR3 = 0x0003,         // ID register 3
  RTLRG_IDR4 = 0x0004,         // ID register 4
  RTLRG_IDR5 = 0x0005,         // ID register 5
  RTLRG_TXSTATUS0 = 0x0010,    // Transmit status of desc 0 (TSD0)
  RTLRG_TXSTATUS1 = 0x0014,    // Transmit status of desc 1 (TSD1)
  RTLRG_TXSTATUS2 = 0x0018,    // Transmit status of desc 2 (TSD2)
  RTLRG_TXSTATUS3 = 0x001c,    // Transmit status of desc 3 (TSD3)
  RTLRG_TXBUF0 = 0x0020,       // Transmit buf start address of desc 0 (TSAD0)
  RTLRG_TXBUF1 = 0x0024,       // Transmit buf start address of desc 1 (TSAD1)
  RTLRG_TXBUF2 = 0x0028,       // Transmit buf start address of desc 2 (TSAD2)
  RTLRG_TXBUF3 = 0x002c,       // Transmit buf start address of desc 3 (TSAD3)
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

// Bits in the transmitter status register.
typedef enum {
  RTL_TSD_OWN = 1 << 13,  // "Own" bit (1 = driven owned)
  RTL_TSD_TOK = 1 << 15,  // TX OK
} rtl_tsd_bits_t;

#define RTL_RXBUF_SIZE 8192
#define RTL_RX_PACKET_HDR_SIZE 4
// 1500 bytes plus 14 bytes of ethernet header
#define RTL_TX_MAX_PACKET_SIZE 1514

// Bits in the received packet header set by the NIC.
typedef enum {
  RTL_RXHDR_ROK = 1 << 0,   // Receive OK
  RTL_RXHDR_BAR = 1 << 13,  // Broadcast address received
  RTL_RXHDR_PAM = 1 << 14,  // Physical address matched
  RTL_RXHDR_MAR = 1 << 15,  // Multicast address recieved
} rtl_rx_header_bits_t;

static int rtl_tx(nic_t* base, pbuf_t* pb) {
  DEFINT_PUSH_AND_DISABLE();
  rtl8139_t* nic = (rtl8139_t*)base;

  // TODO(aoates): queue packets when the NIC is busy.
  if (nic->txbuf_active[nic->txdesc]) {
    KLOG(DEBUG, "tx(%s): unable to tx, next descriptor (%d) is still active\n",
         nic->public.name, nic->txdesc);
    DEFINT_POP();
    return -EBUSY;
  }

  if (pbuf_size(pb) > RTL_TX_MAX_PACKET_SIZE) {
    DEFINT_POP();
    return -EINVAL;
  }

  // TODO(aoates): we own the pbuf...let's try to just use it directly rather
  // than copy.  That would require that it not cross a page boundary.
  KLOG(DEBUG2, "tx(%s): sending packet len %zu on desc %d\n", nic->public.name,
       pbuf_size(pb), nic->txdesc);
  kmemcpy(nic->txbuf[nic->txdesc], pbuf_get(pb), pbuf_size(pb));
  uint16_t tx_port = 0;
  switch (nic->txdesc) {
    case 0: tx_port = RTLRG_TXSTATUS0; break;
    case 1: tx_port = RTLRG_TXSTATUS1; break;
    case 2: tx_port = RTLRG_TXSTATUS2; break;
    case 3: tx_port = RTLRG_TXSTATUS3; break;
    default: die("bad nic state");
  }
  KASSERT((io_read32(nic->io, tx_port) & RTL_TSD_OWN) != 0);
  nic->txbuf_active[nic->txdesc] = true;
  // TODO(aoates): need an appropriate memory barrier here.
  // This sets the size in the lower 12 bits (value checked above), and sets the
  // OWN bit to zero, transferring the buffer to the NIC.
  io_write32(nic->io, tx_port, pbuf_size(pb));
  nic->txdesc++;
  nic->txdesc %= RTL_NUM_TX_DESCS;
  pbuf_free(pb);

  DEFINT_POP();
  return 0;
}

static void rtl_cleanup(nic_t* base) {
  KLOG(DFATAL, "RTL NIC cleanup called (shouldn't be deleted)\n");
}

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
    // TODO(aoates): should we discard the CRC?
    pbuf_t* pb = pbuf_create(0, plen);
    KASSERT(pb != NULL); // TODO(aoates): handle OOM here?

    // Since we set the wrap bit, we can just read the whole packet without
    // worrying about wrapping around the end.
    kmemcpy(pbuf_get(pb), nic->rxbuf + nic->rxstart + RTL_RX_PACKET_HDR_SIZE,
            plen);
    eth_recv(&nic->public, pb);
  } else {
    // TODO(aoates): increment stats.
    KLOG(DEBUG, "received bad packet (status: %#x, len: %d)\n",
         rx_status, plen);
  }

  // Release the buffer space to the NIC.
  nic->rxstart += DWORD_ALIGN(plen + RTL_RX_PACKET_HDR_SIZE);
  nic->rxstart %= RTL_RXBUF_SIZE;
  // N.B.(aoates): it's unclear why we need to offset this by 0x10, but qemu has
  // the reverse transformation in its emulated NIC, and other drivers seem to
  // do this as well.  God forbid the RTL8139 datasheet actually be useful and
  // document this...
  io_write16(nic->io, RTLRG_RXBUF_START, nic->rxstart - 0x10);
}

// Deferred interrupt.
static void rtl_handle_recv(void* arg) {
  rtl8139_t* nic = (rtl8139_t*)arg;
  int packets = 0;
  uint16_t rxbuf_end = ltoh16(io_read16(nic->io, RTLRG_RXBUF_END));
  while (rxbuf_end != nic->rxstart) {
    // TODO(aoates): increment stats?
    packets++;
    int bytes_len =
        (rxbuf_end + RTL_RXBUF_SIZE - nic->rxstart) % RTL_RXBUF_SIZE;
    KLOG(DEBUG2, "recv(%s): start=%#x end=%#x (%d bytes)\n", nic->public.name,
         nic->rxstart, rxbuf_end, bytes_len);
    if (bytes_len < RTL_RX_PACKET_HDR_SIZE) {
      KLOG(INFO, "recv(%s): data in buffer too small!\n", nic->public.name);
      break;
    }
    rtl_handle_recv_one(nic);
    rxbuf_end = ltoh16(io_read16(nic->io, RTLRG_RXBUF_END));
  }
  KLOG(DEBUG2, "recv(%s): read %d packets\n", nic->public.name, packets);
}

// Deferred interrupt.
static void rtl_handle_tx_irq(void* arg) {
  rtl8139_t* nic = (rtl8139_t*)arg;
  for (int i = 0; i < RTL_NUM_TX_DESCS; ++i) {
    const uint16_t tx_status =
        io_read32(nic->io, RTLRG_TXSTATUS0 + (sizeof(uint32_t) * i));
    if (nic->txbuf_active[i]) {
      if (tx_status & RTL_TSD_TOK) {
        KASSERT_DBG(tx_status & RTL_TSD_OWN); // HW error
        KLOG(DEBUG2, "tx(%s): tx OK on descriptor %d\n", nic->public.name, i);
        nic->txbuf_active[i] = false;
      } else {
        // TODO(aoates): handle other scenarios where this assertion would fail
        // (in particular, transmission errors; also potentially a race when
        // setting TOK).
        KASSERT_DBG((tx_status & RTL_TSD_OWN) == 0);
      }
    } else {
      KASSERT_DBG(tx_status & RTL_TSD_OWN);
    }
  }
}

static void rtl_irq_handler(void* arg) {
  rtl8139_t* nic = (rtl8139_t*)arg;
  const uint16_t interrupts = io_read16(nic->io, RTLRG_INTSTATUS);
  if (!interrupts) {
    // Spurious interrupt, ignore.
    return;
  }
  KLOG(DEBUG2, "IRQ received for %s: %#x\n", nic->public.name, interrupts);

  // Clear interrupt bits.  The data sheet says this shouldn't be
  // necessary....but qemu disagrees.
  io_write16(nic->io, RTLRG_INTSTATUS, interrupts);

  if (interrupts & RTL_IMR_ROK) {
    defint_schedule(&rtl_handle_recv, nic);
  }
  if (interrupts & RTL_IMR_TOK) {
    defint_schedule(&rtl_handle_tx_irq, nic);
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
  io_write8(nic->io, RTLRG_CMD, RTL_CMD_RST);
  // Poll until the reset is done.
  // TODO(aoates): if this is slow, make it async so we don't block the full
  // system initialization on it.
  while (io_read8(nic->io, RTLRG_CMD) & RTL_CMD_RST) {
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
  io_write32(nic->io, RTLRG_RBSTART, htol32((uint32_t)phys_rxbuf));

  // Set interrupt mask (rx and tx aren't enabled yet).
  // TODO(aoates): enable other interrupts (errors, in particular).
  io_write16(nic->io, RTLRG_INTMASK, RTL_IMR_TOK | RTL_IMR_ROK);

  // Set reasonable default receive config.  Receive some packets, non-wrap
  // mode, 8k+16 recv buffer size.
  io_write32(nic->io, RTLRG_RXCFG,
       RTL_RCR_AB | RTL_RCR_AM | RTL_RCR_APM | RTL_RCR_WRAP);

  register_irq_handler(pcidev->host_irq, &rtl_irq_handler, nic);

  // Configure transmission.
  KASSERT(PAGE_SIZE / 2 >= RTL_TX_MAX_PACKET_SIZE);
  phys_addr_t txframe1 = page_frame_alloc();
  KASSERT(txframe1 > 0);
  phys_addr_t txframe2 = page_frame_alloc();
  KASSERT(txframe2 > 0);
  const phys_addr_t txbuf0 = txframe1;
  const phys_addr_t txbuf1 = txframe1 + PAGE_SIZE / 2;
  const phys_addr_t txbuf2 = txframe2;
  const phys_addr_t txbuf3 = txframe2 + PAGE_SIZE / 2;
  nic->txbuf[0] = (void*)phys2virt(txbuf0);
  nic->txbuf[1] = (void*)phys2virt(txbuf1);
  nic->txbuf[2] = (void*)phys2virt(txbuf2);
  nic->txbuf[3] = (void*)phys2virt(txbuf3);
  io_write32(nic->io, RTLRG_TXBUF0, htol32((uint32_t)txbuf0));
  io_write32(nic->io, RTLRG_TXBUF1, htol32((uint32_t)txbuf1));
  io_write32(nic->io, RTLRG_TXBUF2, htol32((uint32_t)txbuf2));
  io_write32(nic->io, RTLRG_TXBUF3, htol32((uint32_t)txbuf3));
  nic->txdesc = 0;
  for (int i = 0; i < RTL_NUM_TX_DESCS; ++i) nic->txbuf_active[i] = false;

  // Enable receiving and transmitting.
  KLOG(DEBUG, "Enabling packet rx/tx\n");
  io_write8(nic->io, RTLRG_CMD, RTL_CMD_RX_ENABLE | RTL_CMD_TX_ENABLE);
}

void pci_rtl8139_init(pci_device_t* pcidev) {
  klogf("net: found RTL8139 NIC; initializing\n");
  // TODO(aoates): don't die if we get a bad device.
  KASSERT(pcidev->class_code == 0x02);     // Network controller
  KASSERT(pcidev->subclass_code == 0x00);  // Ethernet

  // We should have two BARs, one for IO-mapped and one for memory-mapped.
  KASSERT(pcidev->bar[0].valid);
  KASSERT(pcidev->bar[0].type == PCIBAR_IO);
  KASSERT(pcidev->bar[1].valid);
  KASSERT(pcidev->bar[1].type == PCIBAR_MEM32);

  rtl8139_t* nic = kmalloc(sizeof(rtl8139_t));
  nic_init(&nic->public);
  nic->public.type = NIC_ETHERNET;
  nic->public.ops = &rtl_ops;
  nic->io = pcidev->bar[0].io;

  // Find the MAC address of the device.
  // N.B.(aoates): the RTL8139 datasheet is contradictory---it says that these
  // can only be accessed in 4-byte chunks...but then says the exact opposite
  // right after.
  nic->public.mac[0] = io_read8(nic->io, RTLRG_IDR0);
  nic->public.mac[1] = io_read8(nic->io, RTLRG_IDR1);
  nic->public.mac[2] = io_read8(nic->io, RTLRG_IDR2);
  nic->public.mac[3] = io_read8(nic->io, RTLRG_IDR3);
  nic->public.mac[4] = io_read8(nic->io, RTLRG_IDR4);
  nic->public.mac[5] = io_read8(nic->io, RTLRG_IDR5);

  nic_create(&nic->public, "eth");
  rtl_init(pcidev, nic);
}

static nic_ops_t rtl_ops = {
  &rtl_tx,
  &rtl_cleanup,
};
