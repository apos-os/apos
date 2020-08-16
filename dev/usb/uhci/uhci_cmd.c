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

#include "arch/common/io.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "dev/usb/bus.h"
#include "dev/usb/hcd.h"
#include "dev/usb/uhci/uhci-internal.h"
#include "dev/usb/uhci/uhci_registers.h"
#include "dev/usb/uhci/uhci.h"
#include "dev/usb/usb.h"
#include "main/kshell.h"
#include "memory/memory.h"
#include "util/flag_printf.h"

static flag_spec_t USBCMD_FLAGS[] = {
  FLAG_SPEC_FLAG("MAXP", 0x0080),
  FLAG_SPEC_FLAG("CF", 0x0040),
  FLAG_SPEC_FLAG("SWDBG", 0x0020),
  FLAG_SPEC_FLAG("FGR", 0x0010),
  FLAG_SPEC_FLAG("EGSM", 0x0008),
  FLAG_SPEC_FLAG("GRESET", 0x0004),
  FLAG_SPEC_FLAG("HCRESET", 0x0002),
  FLAG_SPEC_FLAG("RS", 0x0001),
  FLAG_SPEC_END,
};

static flag_spec_t USBSTS_FLAGS[] = {
  FLAG_SPEC_FLAG("HALTED", 0x0020),
  FLAG_SPEC_FLAG("HCERROR", 0x0010),
  FLAG_SPEC_FLAG("HSYSERROR", 0x0008),
  FLAG_SPEC_FLAG("RESUME", 0x0004),
  FLAG_SPEC_FLAG("ERRINT", 0x0002),
  FLAG_SPEC_FLAG("INT", 0x0001),
  FLAG_SPEC_END,
};

static flag_spec_t USBINTR_FLAGS[] = {
  FLAG_SPEC_FLAG("SHORTP", 0x0008),
  FLAG_SPEC_FLAG("IOC", 0x0004),
  FLAG_SPEC_FLAG("RESUME", 0x0002),
  FLAG_SPEC_FLAG("TMO_CRC", 0x0001),
  FLAG_SPEC_END,
};

static flag_spec_t PORTSC_FLAGS[] = {
  FLAG_SPEC_FLAG("SUSPEND", 0x1000),
  FLAG_SPEC_FLAG("RST", 0x0200),
  FLAG_SPEC_FLAG("LOSPEED", 0x0100),
  FLAG_SPEC_FLAG("RESUME_DTCT", 0x0040),
  FLAG_SPEC_FIELD("LINE_STATUS", 0x0030, 4),
  FLAG_SPEC_FLAG("ENABLE_CHG", 0x0008),
  FLAG_SPEC_FLAG("ENABLE", 0x0004),
  FLAG_SPEC_FLAG("CONNECT_CHG", 0x0002),
  FLAG_SPEC_FLAG("CONNECT", 0x0001),
  FLAG_SPEC_END,
};

//static flag_spec_t FL_PTR_FLAGS[] = {
//  FLAG_SPEC_FIELD("ADDR", 0xFFFFFFF0, 0),
//  FLAG_SPEC_FLAG("QH", 0x00000002),
//  FLAG_SPEC_FLAG("TERM", 0x00000001),
//  FLAG_SPEC_END,
//};

static flag_spec_t TD_LINK_PTR_FLAGS[] = {
  FLAG_SPEC_FIELD("ADDR", 0xFFFFFFF0, 0),
  FLAG_SPEC_FLAG("VF", 0x04),
  FLAG_SPEC_FLAG("QH", 0x02),
  FLAG_SPEC_FLAG("TERM", 0x01),
  FLAG_SPEC_END,
};

static flag_spec_t TD_SC_FLAGS[] = {
  FLAG_SPEC_FLAG("SPD", 0x20000000),
  FLAG_SPEC_FIELD("ERR", 0x18000000, 24),
  FLAG_SPEC_FLAG("LS", 0x04000000),
  FLAG_SPEC_FLAG("IOS", 0x02000000),
  FLAG_SPEC_FLAG("IOC", 0x01000000),
  FLAG_SPEC_FLAG2("STS_ACTIVE", "STS_INACTIVE", 0x00800000),
  FLAG_SPEC_FLAG("STS_STALLED", 0x00400000),
  FLAG_SPEC_FLAG("STS_DBUF_ERR", 0x00200000),
  FLAG_SPEC_FLAG("STS_BABBLE", 0x00100000),
  FLAG_SPEC_FLAG("STS_NAK", 0x00080000),
  FLAG_SPEC_FLAG("STS_TOCRC_ERR", 0x00040000),
  FLAG_SPEC_FLAG("STS_BITSF_ERR", 0x00020000),
  FLAG_SPEC_FIELD("ACTLEN", 0x000007FF, 0),
  FLAG_SPEC_END,
};

static flag_spec_t TD_TOK_FLAGS[] = {
  FLAG_SPEC_FIELD("MAXLEN", 0xFFE00000, 21),
  FLAG_SPEC_FLAG2("DATA1", "DATA0", 0x00080000),
  FLAG_SPEC_FIELD("ENDPT", 0x00078000, 15),
  FLAG_SPEC_FIELD("DADDR", 0x00007F00, 8),
  FLAG_SPEC_FIELD("PID", 0x000000FF, 0),
  FLAG_SPEC_END,
};

static flag_spec_t QH_FLAGS[] = {
  FLAG_SPEC_FIELD("ADDR", 0xFFFFFFF0, 0),
  FLAG_SPEC_FLAG2("QH", "TD", 0x00000002),
  FLAG_SPEC_FLAG("TERM", 0x00000001),
  FLAG_SPEC_END,
};

static void print_td(uhci_td_t* td) {
  // If the address is physical, convert to virtual before reading it.
  if (is_direct_mappable((phys_addr_t)td)) {
    td = (uhci_td_t*)phys2virt((phys_addr_t)td);
  }
  char buf[1024];
  flag_sprintf(buf, td->link_ptr, TD_LINK_PTR_FLAGS);
  ksh_printf("  LINK_PTR: %s\n", buf);
  flag_sprintf(buf, td->status_ctrl, TD_SC_FLAGS);
  ksh_printf("  STATUS_CTRL: %s\n", buf);
  flag_sprintf(buf, td->token, TD_TOK_FLAGS);
  ksh_printf("  TOKEN: %s\n", buf);
  ksh_printf("  BUFFER: 0x%x\n", td->buf_ptr);
  ksh_printf("  DATA[0]: 0x%x\n", td->data[0]);
  ksh_printf("  DATA[1]: 0x%x\n", td->data[1]);
  ksh_printf("  DATA[2]: 0x%x\n", td->data[2]);
  ksh_printf("  DATA[3]: 0x%x\n", td->data[3]);
}

static void print_qh(uhci_qh_t* qh) {
  // If the address is physical, convert to virtual before reading it.
  if (is_direct_mappable((phys_addr_t)qh)) {
    qh = (uhci_qh_t*)phys2virt((phys_addr_t)qh);
  }
  char buf[1024];
  flag_sprintf(buf, qh->head_link_ptr, QH_FLAGS);
  ksh_printf("  HEAD_LINK_PTR: %s\n", buf);
  flag_sprintf(buf, qh->elt_link_ptr, QH_FLAGS);
  ksh_printf("  ELT_LINK_PTR: %s\n", buf);
}

static void uhci_cmd_test(int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: uhci test <controller idx> <port>\n");
    return;
  }
  int idx = katoi(argv[2]);
  int port = katoi(argv[3]);
  if (idx >= usb_num_buses()) {
    ksh_printf("error: invalid controller %d\n", idx);
    return;
  }
  // Test the USB controller.
  uhci_test_controller(usb_get_bus(idx)->hcd, port);
}

static void uhci_cmd_ls(int argc, char* argv[]) {
  if (argc != 2 && argc != 3) {
    ksh_printf("usage: uhci ls [idx]\n");
    return;
  }
  PUSH_AND_DISABLE_INTERRUPTS();
  if (argc == 2) {
    // FIXME(aoates): this will break when we add other controller types!
    for (int i = 0; i < usb_num_buses(); ++i) {
      usb_uhci_t* hc = (usb_uhci_t*)usb_get_bus(i)->hcd->dev_data;
      ksh_printf("USB %d: port: 0x%x\n", i, hc->base_port);
    }
  } else {
    int idx = katoi(argv[2]);
    if (idx >= usb_num_buses()) {
      ksh_printf("error: invalid controller %d\n", idx);
      return;
    }
    usb_uhci_t* hc = (usb_uhci_t*)usb_get_bus(idx)->hcd->dev_data;

    // Get the current state.
    uint16_t usbcmd = ins(hc->base_port + USBCMD);
    uint16_t usbsts = ins(hc->base_port + USBSTS);
    uint16_t usbintr = ins(hc->base_port + USBINTR);
    uint16_t frnum = ins(hc->base_port + FRNUM);
    uint32_t flbaseaddr = inl(hc->base_port + FLBASEADDR);
    uint8_t sof_modify = inb(hc->base_port + SOF_MODIFY);
    uint16_t portsc1 = ins(hc->base_port + PORTSC1);
    uint16_t portsc2 = ins(hc->base_port + PORTSC2);

    // Print the registers.
    char buf[1024];
    ksh_printf("USB %d: port: 0x%x\n", idx, hc->base_port);
    flag_sprintf(buf, usbcmd, USBCMD_FLAGS); ksh_printf("  USBCMD: %s\n", buf);
    flag_sprintf(buf, usbsts, USBSTS_FLAGS); ksh_printf("  USBSTS: %s\n", buf);
    flag_sprintf(buf, usbintr, USBINTR_FLAGS); ksh_printf("  USBINTR: %s\n", buf);
    ksh_printf("  FRNUM: 0x%x\n", frnum);
    ksh_printf("  FLBASEADDR: 0x%x\n", flbaseaddr);
    ksh_printf("  SOF_MODIFY: 0x%x\n", sof_modify);
    flag_sprintf(buf, portsc1, PORTSC_FLAGS); ksh_printf("  PORTSC1: %s\n", buf);
    flag_sprintf(buf, portsc2, PORTSC_FLAGS); ksh_printf("  PORTSC2: %s\n", buf);
  }
  POP_INTERRUPTS();
}

static void uhci_cmd_td(int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: uhci td <address>\n");
    return;
  }
  addr_t address = katou(argv[2]);
  print_td((uhci_td_t*)address);
}

static void uhci_cmd_qh(int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: uhci qh <address>\n");
    return;
  }
  addr_t address = katou(argv[2]);
  print_qh((uhci_qh_t*)address);
}

// Test the UHCI controller(s).
void uhci_cmd(int argc, char* argv[]) {
  if (argc < 2) {
    ksh_printf("usage: uhci <cmd> <args> ...\n");
    return;
  }
  if (kstrcmp(argv[1], "test") == 0) {
    uhci_cmd_test(argc, argv);
  } else if (kstrcmp(argv[1], "ls") == 0) {
    uhci_cmd_ls(argc, argv);
  } else if (kstrcmp(argv[1], "td") == 0) {
    uhci_cmd_td(argc, argv);
  } else if (kstrcmp(argv[1], "qh") == 0) {
    uhci_cmd_qh(argc, argv);
  } else {
    ksh_printf("error: unknown command '%s'\n", argv[1]);
  }
}
