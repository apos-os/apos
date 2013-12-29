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

#include "common/io.h"
#include "common/math.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/errno.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "dev/usb/drivers/hub.h"
#include "dev/usb/uhci/uhci-internal.h"
#include "dev/usb/uhci/uhci.h"
#include "dev/usb/uhci/uhci_hub.h"
#include "dev/usb/uhci/uhci_registers.h"
#include "memory/kmalloc.h"

// Length of time to hold down the reset line for a port.
#define UHCI_PORT_RESET_MS 10

// Interval for status change endpoint.
#define UHCI_HUB_STATUS_CHANGE_INTERVAL 0xFF

// The only configuration supported.
#define UHCI_HUB_CONFIG 1

// The only interface supported.
#define UHCI_HUB_IFACE 0

// Endpoint number for the status change endpoint.
#define UHCI_HUB_STATUS_CHANGE 1

int uhci_hub_init(usb_uhci_t* hc) {
  uhci_hub_t* hub = (uhci_hub_t*)kmalloc(sizeof(uhci_hub_t));
  if (!hub) {
    return -ENOMEM;
  }

  hub->hc = hc;
  hub->state = DEFAULT;
  hub->dcp_irp_state = IRP_SETUP;
  hub->c_port_suspend[0] = hub->c_port_suspend[1] = 0;
  hub->c_port_reset[0] = hub->c_port_reset[1] = 0;
  hub->address = USB_DEFAULT_ADDRESS;

  hc->root_hub = hub;
  return 0;
}

// Copy a flag from one bitset to another.
inline static void COPY_FLAG(uint16_t port_status, uint16_t* out,
                             uint16_t flag_in, uint16_t flag_out) {
  if (port_status & flag_in) {
    *out |= flag_out;
  }
}

// Handlers for each of the request types.  The handlers are responsible for,
//   a) handling both DATA and STATUS stages of the request
//   b) copying any data (in the DATA stage), if necessary.
//   c) setting the IRP's out_len and status fields as needed.
static int handle_GET_STATUS(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  if (hub->dcp_irp_state == IRP_STATUS) {
    KASSERT(irp->pid == USB_PID_OUT);
    irp->status = USB_IRP_SUCCESS;
    irp->out_len = 0;
    return 0; // STATUS phase is a (successful) no-op.
  }

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT(hub->dcp_irp_state == IRP_DATA);
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_DEV2HOST);
  KASSERT(req->bRequest == USB_DEVREQ_GET_STATUS);
  KASSERT(req->wValue == 0);
  KASSERT(irp->pid == USB_PID_IN);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  if (type == USB_DEVREQ_TYPE_STD) {
    KASSERT(req->wLength == 2);
    uint16_t* data_out = (uint16_t*)irp->buffer;
    irp->out_len = 2;
    switch (rcpt) {
      case USB_DEVREQ_RCPT_DEV:
        *data_out = USB_GET_STATUS_DEV_SELF_PWR;
        break;

      case USB_DEVREQ_RCPT_IFACE:
        KASSERT(req->wIndex == UHCI_HUB_IFACE);
        *data_out = 0x0;
        break;

      case USB_DEVREQ_RCPT_ENDPT:
        KASSERT(req->wIndex == USB_DEFAULT_CONTROL_PIPE ||
                req->wIndex == UHCI_HUB_STATUS_CHANGE);
        // For both endpoints, just use the halted bit from the controller.
        uint16_t status = ins(hub->hc->base_port + USBSTS);
        if (status & USBSTS_HALTED) {
          *data_out = USB_GET_STATUS_ENDPT_HALT;
        } else {
          *data_out = 0x0;
        }
        break;

      default:
        die("invalid rcpt type in UHCI GET_STATUS request");
    }
  } else if (type == USB_DEVREQ_TYPE_CLASS) {
    KASSERT(req->wLength == 4);
    irp->out_len = 4;
    uint16_t* data_out = (uint16_t*)irp->buffer;
    uint16_t* change_out = data_out + 1;
    int port;
    switch (rcpt) {
      case USB_DEVREQ_RCPT_DEV:
        KASSERT(req->wIndex == 0);
        *data_out = 0x0;
        *change_out = 0x0;
        break;

      case USB_DEVREQ_RCPT_OTHER:
        port = req->wIndex;
        KASSERT(port == 1 || port == 2);
        *data_out = 0x0;
        *change_out = 0x0;
        const uint16_t port_sc =
            ins(hub->hc->base_port + (port == 1 ? PORTSC1 : PORTSC2));

        COPY_FLAG(port_sc, data_out, PORTSC_CONNECT, USB_HUBD_PORT_CONNECTION);
        COPY_FLAG(port_sc, change_out, PORTSC_CONNECT_CHG, USB_HUBD_C_PORT_CONNECTION);
        COPY_FLAG(port_sc, data_out, PORTSC_ENABLE, USB_HUBD_PORT_ENABLE);
        COPY_FLAG(port_sc, change_out, PORTSC_ENABLE_CHG, USB_HUBD_C_PORT_ENABLE);
        COPY_FLAG(port_sc, data_out, PORTSC_SUSPEND, USB_HUBD_PORT_SUSPEND);
        if (hub->c_port_suspend[port-1]) *change_out |= USB_HUBD_C_PORT_SUSPEND;
        // Never set over-current flags.
        COPY_FLAG(port_sc, data_out, PORTSC_RST, USB_HUBD_PORT_RESET);
        {
          PUSH_AND_DISABLE_INTERRUPTS();
          if (hub->c_port_reset[port-1]) *change_out |= USB_HUBD_C_PORT_RESET;
          POP_INTERRUPTS();
        }
        COPY_FLAG(port_sc, data_out, PORTSC_LOSPEED, USB_HUBD_PORT_LOW_SPEED);
        break;

      default:
        die("invalid rcpt type in UHCI GET_STATUS request");
    }
  } else {
    die("invalid request type (not standard or class!)");
  }

  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_CLEAR_FEATURE(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  KASSERT(hub->dcp_irp_state == IRP_STATUS);
  KASSERT(irp->pid == USB_PID_IN);

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_HOST2DEV);
  KASSERT(req->bRequest == USB_DEVREQ_CLEAR_FEATURE);
  KASSERT(req->wLength == 0);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  if (type == USB_DEVREQ_TYPE_STD) {
    // TODO(aoates): support the standard features.
    die("UHCI fake hub controller doesn't support standard features :(");
  } else if (type == USB_DEVREQ_TYPE_CLASS) {
    switch (rcpt) {
      case USB_DEVREQ_RCPT_DEV:
        KASSERT(req->wIndex == 0);
        // No-op.  We don't need to handle either C_HUB_LOCAL_POWER or
        // C_HUB_OVER_CURRENT.
        break;

      case USB_DEVREQ_RCPT_OTHER: {
        const int port = req->wIndex & 0x00FF;
        const int feat = req->wValue;
        KASSERT(port == 1 || port == 2);

        const uint16_t port_sc_register =
            hub->hc->base_port + (port == 1 ? PORTSC1 : PORTSC2);
        uint16_t port_sc = ins(port_sc_register);

        switch (feat) {
          case USB_HUBD_FEAT_PORT_ENABLE:
            port_sc &= ~PORTSC_ENABLE;
            outs(port_sc_register, port_sc);
            break;

          case USB_HUBD_FEAT_PORT_SUSPEND:
            die("UHCI: suspend unimplemented!");

          case USB_HUBD_FEAT_PORT_POWER:
            // TODO(aoates): I don't think this should be a panic.  Read up on
            // the spec and figure out the right way to handle it.
            die("UHCI: cannot power off root-hub port");

          case USB_HUBD_FEAT_C_PORT_CONNECTION:
            port_sc |= PORTSC_CONNECT_CHG;
            outs(port_sc_register, port_sc);
            break;

          case USB_HUBD_FEAT_C_PORT_ENABLE:
            port_sc |= PORTSC_ENABLE_CHG;
            outs(port_sc_register, port_sc);
            break;

          case USB_HUBD_FEAT_C_PORT_SUSPEND:
            hub->c_port_suspend[port-1] = 0;
            break;

          case USB_HUBD_FEAT_C_PORT_RESET:
            {
              PUSH_AND_DISABLE_INTERRUPTS();
              hub->c_port_reset[port-1] = 0;
              POP_INTERRUPTS();
            }
            break;

          case USB_HUBD_FEAT_PORT_INDICATOR:
          case USB_HUBD_FEAT_C_PORT_OVER_CURRENT:
            break;  // No-op.

          case USB_HUBD_FEAT_PORT_LOW_SPEED:
          case USB_HUBD_FEAT_PORT_OVER_CURRENT:
          case USB_HUBD_FEAT_PORT_RESET:
          case USB_HUBD_FEAT_PORT_TEST:
          case USB_HUBD_FEAT_PORT_CONNECTION:
          default:
            klogf("unsupported ClearPortFeature feature: %d\n", feat);
            die("unsupported ClearPortFeature in UHCI root hub cntlr");
        }
        break;
      }
      default:
        klogf("unsupported ClearPortFeature rcpt: %d\n", rcpt);
        die("unsupported ClearPortFeature rcpt");
    }
  } else {
    die("UHCI: unknown type in CLEAR_FEATURE\n");
  }

  irp->out_len = 0;
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

// Called on an interrupt context when a port reset is done.
struct uhci_port_reset_done_arg {
  uhci_hub_t* hub;
  int port;
};
typedef struct uhci_port_reset_done_arg uhci_port_reset_done_arg_t;

static void uhci_port_reset_done(void* arg) {
  uhci_port_reset_done_arg_t* args = (uhci_port_reset_done_arg_t*)arg;

  KASSERT(args->port == 1 || args->port == 2);

  const uint16_t port_sc_register =
      args->hub->hc->base_port + (args->port == 1 ? PORTSC1 : PORTSC2);
  uint16_t port_sc = ins(port_sc_register);
  KASSERT(port_sc & PORTSC_RST);

  // Stop resetting.
  port_sc &= ~PORTSC_RST;
  outs(port_sc_register, port_sc);

  // Signal the reset is done.
  args->hub->c_port_reset[args->port-1] = 1;
  kfree(args);

  // TODO(aoates): signal on the status change endpoint?
}

static int handle_SET_FEATURE(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  KASSERT(hub->dcp_irp_state == IRP_STATUS);
  KASSERT(irp->pid == USB_PID_IN);

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_HOST2DEV);
  KASSERT(req->bRequest == USB_DEVREQ_SET_FEATURE);
  KASSERT(req->wLength == 0);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  if (type == USB_DEVREQ_TYPE_STD) {
    // TODO(aoates): support the standard features.
    die("UHCI fake hub controller doesn't support standard features :(");
  } else if (type == USB_DEVREQ_TYPE_CLASS) {
    switch (rcpt) {
      // SetHubFeature
      case USB_DEVREQ_RCPT_DEV:
        KASSERT(req->wIndex == 0);
        die("UHCI: SetHubFeature should never be called");

      // SetPortFeature
      case USB_DEVREQ_RCPT_OTHER: {
        const int port = req->wIndex & 0x00FF;
        const int feat = req->wValue;
        KASSERT(port == 1 || port == 2);

        const uint16_t port_sc_register =
            hub->hc->base_port + (port == 1 ? PORTSC1 : PORTSC2);
        uint16_t port_sc = ins(port_sc_register);

        switch (feat) {
          case USB_HUBD_FEAT_PORT_RESET:
            // Kick off a reset, then set a timer to stop the reset and set the
            // C_PORT_RESET bit to 1.
            if ((port_sc & PORTSC_RST) == 0) {
              port_sc |= PORTSC_RST;
              outs(port_sc_register, port_sc);
              uhci_port_reset_done_arg_t* arg = (uhci_port_reset_done_arg_t*)
                  kmalloc(sizeof(uhci_port_reset_done_arg_t));
              arg->hub = hub;
              arg->port = port;
              register_event_timer(get_time_ms() + UHCI_PORT_RESET_MS,
                                   &uhci_port_reset_done, arg, 0x0);
            }
            break;

            // TODO NYI

          case USB_HUBD_FEAT_PORT_POWER:
            // TODO(aoates): I don't think this should be a panic.  Read up on
            // the spec and figure out the right way to handle it.
            die("UHCI: cannot power off root-hub port");

          case USB_HUBD_FEAT_PORT_TEST:
            die("UHCI: port test unimplemented!");

          case USB_HUBD_FEAT_PORT_SUSPEND:
            die("UHCI: suspend unimplemented!");

          case USB_HUBD_FEAT_C_PORT_CONNECTION:
          case USB_HUBD_FEAT_C_PORT_ENABLE:
          case USB_HUBD_FEAT_C_PORT_SUSPEND:
          case USB_HUBD_FEAT_C_PORT_RESET:
          case USB_HUBD_FEAT_C_PORT_OVER_CURRENT:
          case USB_HUBD_FEAT_PORT_INDICATOR:
            break;  // No-op.

          case USB_HUBD_FEAT_PORT_LOW_SPEED:
          case USB_HUBD_FEAT_PORT_OVER_CURRENT:
          case USB_HUBD_FEAT_PORT_CONNECTION:
          case USB_HUBD_FEAT_PORT_ENABLE:
          default:
            klogf("unsupported ClearPortFeature feature: %d\n", feat);
            die("unsupported ClearPortFeature in UHCI root hub cntlr");
        }
        break;
      }
      default:
        klogf("unsupported ClearPortFeature rcpt: %d\n", rcpt);
        die("unsupported ClearPortFeature rcpt");
    }
  } else {
    die("UHCI: unknown type in CLEAR_FEATURE\n");
  }

  irp->out_len = 0;
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_SET_ADDRESS(uhci_hub_t* hubc, usb_hcdi_irp_t* irp) {
  KASSERT(hubc->dcp_irp_state == IRP_STATUS);
  KASSERT(irp->pid == USB_PID_IN);

  const usb_dev_request_t* req = &hubc->dcp_request;
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_HOST2DEV);
  KASSERT(req->bRequest == USB_DEVREQ_SET_ADDRESS);
  KASSERT(req->wLength == 0);
  KASSERT(req->wIndex == 0);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  KASSERT(type == USB_DEVREQ_TYPE_STD);
  KASSERT(rcpt == USB_DEVREQ_RCPT_DEV);
  const uint16_t address = req->wValue;
  KASSERT(address <= 127);

  if (hubc->state == DEFAULT) {
    if (address > 0) {
      hubc->address = address;
      hubc->state = ADDRESS;
    }
  } else if (hubc->state == ADDRESS) {
    if (address == 0) {
      hubc->state = DEFAULT;
    } else {
      hubc->address = address;
    }
  } else {
    die("UHCI: cannot SET_ADDRESS in non-DEFAULT/ADDRESS state");
  }

  irp->out_len = 0;
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_GET_DESCRIPTOR(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  if (hub->dcp_irp_state == IRP_STATUS) {
    KASSERT(irp->pid == USB_PID_OUT);
    irp->status = USB_IRP_SUCCESS;
    irp->out_len = 0;
    return 0; // STATUS phase is a (successful) no-op.
  }

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT(hub->dcp_irp_state == IRP_DATA);
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_DEV2HOST);
  KASSERT(req->bRequest == USB_DEVREQ_GET_DESCRIPTOR);
  KASSERT(irp->pid == USB_PID_IN);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  const uint8_t desc_type = (req->wValue >> 8) & 0x00FF;
  const uint8_t desc_idx = req->wValue & 0x00FF;
  if (type == USB_DEVREQ_TYPE_STD) {
    KASSERT(rcpt == USB_DEVREQ_RCPT_DEV);
    switch (desc_type) {
      case USB_DESC_DEVICE: {
        usb_desc_dev_t desc;
        kmemset(&desc, 0, sizeof(usb_desc_dev_t));
        desc.bLength = sizeof(usb_desc_dev_t);
        desc.bDescriptorType = USB_DESC_DEVICE;
        desc.bcdUSB = 0x0110;
        desc.bDeviceClass = USB_CLASS_HUB;
        desc.bDeviceSubClass = 0;
        desc.bDeviceProtocol = 0;
        desc.bMaxPacketSize0 = 64;
        desc.bNumConfigurations = 1;

        const int bytes_to_copy = min(irp->buflen, desc.bLength);
        kmemcpy(irp->buffer, &desc, bytes_to_copy);
        irp->out_len = bytes_to_copy;
        break;
      }
      case USB_DESC_CONFIGURATION: {
        KASSERT(desc_idx == 0);
        // First, fill in the configuration, interface, and endpoint
        // descriptors.
        // TODO(aoates): do we need to return the hub descriptor interleaved?
        usb_desc_config_t desc_config;
        usb_desc_interface_t desc_interface;
        usb_desc_endpoint_t desc_endpoint;

        desc_config.bLength = sizeof(usb_desc_config_t);
        desc_config.bDescriptorType = USB_DESC_CONFIGURATION;
        // TODO(aoates): update this if we add other descriptors.
        desc_config.wTotalLength =
            sizeof(usb_desc_config_t) + sizeof(usb_desc_interface_t) +
            sizeof(usb_desc_endpoint_t);
        desc_config.bNumInterfaces = 1;
        desc_config.bConfigurationValue = UHCI_HUB_CONFIG;
        desc_config.iConfiguration = 0;
        desc_config.bmAttributes = USB_DESC_CONFIG_BMATTR_SELF_POWERED;
        desc_config.bMaxPower = 0;

        desc_interface.bLength = sizeof(usb_desc_interface_t);
        desc_interface.bDescriptorType = USB_DESC_INTERFACE;
        desc_interface.bInterfaceNumber = 0;
        desc_interface.bAlternateSetting = 0;
        desc_interface.bNumEndpoints = 1;
        desc_interface.bInterfaceClass = USB_CLASS_HUB;
        desc_interface.bInterfaceSubClass = 0;
        desc_interface.bInterfaceProtocol = 0;
        desc_interface.iInterface = 0;

        desc_endpoint.bLength = sizeof(usb_desc_endpoint_t);
        desc_endpoint.bDescriptorType = USB_DESC_ENDPOINT;
        desc_endpoint.bEndpointAddress =
            USB_DESC_ENDPOINT_DIR_IN | UHCI_HUB_STATUS_CHANGE;
        desc_endpoint.bmAttributes =
            USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_INTERRUPT;
        desc_endpoint.wMaxPacketSize = 64;
        desc_endpoint.bInterval = UHCI_HUB_STATUS_CHANGE_INTERVAL;

        // Copy the descriptors into the buffer, as far as we can go.
        unsigned int bytes_left = irp->buflen;
        char* bufptr = (char*)irp->buffer;
        if (bytes_left > 0) {
          const int bytes_to_copy = min(bytes_left, sizeof(usb_desc_config_t));
          kmemcpy(bufptr, &desc_config, bytes_to_copy);
          bufptr += bytes_to_copy;
          bytes_left -= bytes_to_copy;
        }

        if (bytes_left > 0) {
          const int bytes_to_copy =
              min(bytes_left, sizeof(usb_desc_interface_t));
          kmemcpy(bufptr, &desc_interface, bytes_to_copy);
          bufptr += bytes_to_copy;
          bytes_left -= bytes_to_copy;
        }

        if (bytes_left > 0) {
          const int bytes_to_copy =
              min(bytes_left, sizeof(usb_desc_endpoint_t));
          kmemcpy(bufptr, &desc_endpoint, bytes_to_copy);
          bufptr += bytes_to_copy;
          bytes_left -= bytes_to_copy;
        }

        irp->out_len = irp->buflen - bytes_left;
        break;
      }

      case USB_DESC_STRING:
      default:
        klogf("unsupported descriptor type in GET_DESCRIPTOR: %d\n", desc_type);
        die("unsupported descriptor type in GET_DESCRIPTOR");
    }
  } else if (type == USB_DEVREQ_TYPE_CLASS) {
    KASSERT(rcpt == USB_DEVREQ_RCPT_DEV);
    KASSERT(desc_type == USB_HUBD_DESC_TYPE);
    KASSERT(desc_idx == 0);

    const int desc_len = sizeof(usb_hubd_desc_t) + 2;
    char desc_buf[desc_len];
    usb_hubd_desc_t* desc = (usb_hubd_desc_t*)desc_buf;

    desc->bLength = desc_len;
    desc->bDescriptorType = USB_HUBD_DESC_TYPE;
    desc->bNbrPorts = 2;
    desc->wHubCharacteristics =
        USB_HUBD_CHAR_LPSM_GANGED |
        USB_HUBD_CHAR_OCPM_NONE1;
    desc->bPwrOn2PwrGood = 0;
    desc->bHubContrCurrent = 0;
    desc->PortBits[0] = 0x0;
    desc->PortBits[1] = 0xFF;

    const int bytes_to_copy = min(irp->buflen, desc->bLength);
    kmemcpy(irp->buffer, &desc, bytes_to_copy);
    irp->out_len = bytes_to_copy;
  } else {
    klogf("UHCI: unsupported request type in GET_DESCRIPTOR: %d\n", type);
    die("UHCI: unsupported request type in GET_DESCRIPTOR");
  }
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_SET_DESCRIPTOR(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  die("UHCI: SET_DESCRIPTOR unsupported");
  return 0;
}

static int handle_GET_CONFIGURATION(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  if (hub->dcp_irp_state == IRP_STATUS) {
    KASSERT(irp->pid == USB_PID_OUT);
    irp->status = USB_IRP_SUCCESS;
    irp->out_len = 0;
    return 0; // STATUS phase is a (successful) no-op.
  }

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT(hub->dcp_irp_state == IRP_DATA);
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_DEV2HOST);
  KASSERT(req->bRequest == USB_DEVREQ_GET_CONFIGURATION);
  KASSERT(req->wValue == 0);
  KASSERT(req->wIndex == 0);
  KASSERT(req->wLength == 1);
  KASSERT(irp->pid == USB_PID_IN);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  KASSERT(type == USB_DEVREQ_TYPE_STD);
  KASSERT(rcpt == USB_DEVREQ_RCPT_DEV);
  KASSERT(hub->state != DEFAULT);

  uint8_t* data_out = (uint8_t*)irp->buffer;
  switch (hub->state) {
    case ADDRESS:
      *data_out = USB_NO_CONFIGURATION;
      break;

    case CONFIGURED:
      *data_out = UHCI_HUB_CONFIG;
      break;

    default:
      die("invalid UHCI hub state");
  }

  irp->out_len = 1;
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_SET_CONFIGURATION(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  KASSERT(hub->dcp_irp_state == IRP_STATUS);
  KASSERT(irp->pid == USB_PID_IN);

  const usb_dev_request_t* req = &hub->dcp_request;
  KASSERT((req->bmRequestType & USB_DEVREQ_DIR_MASK)
          == USB_DEVREQ_DIR_HOST2DEV);
  KASSERT(req->bRequest == USB_DEVREQ_SET_CONFIGURATION);
  KASSERT(req->wLength == 0);
  KASSERT(req->wIndex == 0);

  const uint8_t type = req->bmRequestType & USB_DEVREQ_TYPE_MASK;
  const uint8_t rcpt = req->bmRequestType & USB_DEVREQ_RCPT_MASK;
  KASSERT(type == USB_DEVREQ_TYPE_STD);
  KASSERT(rcpt == USB_DEVREQ_RCPT_DEV);
  const uint16_t configuration = req->wValue;
  KASSERT(configuration == USB_NO_CONFIGURATION || configuration == UHCI_HUB_CONFIG);
  KASSERT(hub->state != DEFAULT);

  switch (hub->state) {
    case ADDRESS:
      if (configuration != USB_NO_CONFIGURATION) {
        hub->state = CONFIGURED;
      }
      break;

    case CONFIGURED:
      if (configuration == USB_NO_CONFIGURATION) {
        hub->state = ADDRESS;
      }
      break;

    default:
      die("invalid UHCI hub state");
  }

  irp->out_len = 0;
  irp->status = USB_IRP_SUCCESS;
  return 0;
}

static int handle_dcp_irp(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  int status = 0;
  switch (hub->dcp_irp_state) {
    case IRP_SETUP:
      KASSERT(irp->pid == USB_PID_SETUP);
      KASSERT(irp->endpoint->data_toggle == USB_DATA0);
      KASSERT(irp->buflen == sizeof(usb_dev_request_t));

      // Save the request for later.
      kmemcpy(&hub->dcp_request, irp->buffer, sizeof(usb_dev_request_t));

      irp->status = USB_IRP_SUCCESS;
      irp->out_len = irp->buflen;
      // Depending on the request type, determine if we need expect a data
      // packet.
      switch (hub->dcp_request.bRequest) {
        case USB_DEVREQ_GET_STATUS:
        case USB_DEVREQ_GET_DESCRIPTOR:
        case USB_DEVREQ_SET_DESCRIPTOR:
        case USB_DEVREQ_GET_CONFIGURATION:
          hub->dcp_irp_state = IRP_DATA;
          break;

        case USB_DEVREQ_CLEAR_FEATURE:
        case USB_DEVREQ_SET_CONFIGURATION:
        case USB_DEVREQ_SET_ADDRESS:
        case USB_DEVREQ_SET_FEATURE:
          hub->dcp_irp_state = IRP_STATUS;
          break;

        case USB_DEVREQ_GET_INTERFACE:
        case USB_DEVREQ_SET_INTERFACE:
        case USB_DEVREQ_SYNCH_FRAME:
        default:
          klogf("error: unsupported bRequest in UHCI hub controller: %d\n",
                hub->dcp_request.bRequest);
          die("unsupported bRequest in UHCI hub controller");
      }
      break;

    // Note: we expect the data stage to be one big IRP (that is, it shouldn't
    // be split up into multiple packets).
    case IRP_DATA:
      if ((hub->dcp_request.bmRequestType & USB_DEVREQ_DIR_MASK) ==
          USB_DEVREQ_DIR_DEV2HOST) {
        KASSERT(irp->pid == USB_PID_IN);
      } else {
        KASSERT(irp->pid == USB_PID_OUT);
      }

      switch (hub->dcp_request.bRequest) {
        case USB_DEVREQ_GET_STATUS: status = handle_GET_STATUS(hub, irp); break;
        case USB_DEVREQ_CLEAR_FEATURE: status = handle_CLEAR_FEATURE(hub, irp); break;
        case USB_DEVREQ_SET_FEATURE: status = handle_SET_FEATURE(hub, irp); break;
        case USB_DEVREQ_SET_ADDRESS: status = handle_SET_ADDRESS(hub, irp); break;
        case USB_DEVREQ_GET_DESCRIPTOR: status = handle_GET_DESCRIPTOR(hub, irp); break;
        case USB_DEVREQ_SET_DESCRIPTOR: status = handle_SET_DESCRIPTOR(hub, irp); break;
        case USB_DEVREQ_GET_CONFIGURATION: status = handle_GET_CONFIGURATION(hub, irp); break;
        case USB_DEVREQ_SET_CONFIGURATION: status = handle_SET_CONFIGURATION(hub, irp); break;
        default:
          die("unsupported bRequest in UHCI hub controller");
      }

      hub->dcp_irp_state = IRP_STATUS;
      break;

    case IRP_STATUS:
      // The status packet should be the *opposite* of the data packet.
      if ((hub->dcp_request.bmRequestType & USB_DEVREQ_DIR_MASK) ==
          USB_DEVREQ_DIR_DEV2HOST) {
        KASSERT(irp->pid == USB_PID_OUT);
      } else {
        KASSERT(irp->pid == USB_PID_IN);
      }

      switch (hub->dcp_request.bRequest) {
        case USB_DEVREQ_GET_STATUS: status = handle_GET_STATUS(hub, irp); break;
        case USB_DEVREQ_CLEAR_FEATURE: status = handle_CLEAR_FEATURE(hub, irp); break;
        case USB_DEVREQ_SET_FEATURE: status = handle_SET_FEATURE(hub, irp); break;
        case USB_DEVREQ_SET_ADDRESS: status = handle_SET_ADDRESS(hub, irp); break;
        case USB_DEVREQ_GET_DESCRIPTOR: status = handle_GET_DESCRIPTOR(hub, irp); break;
        case USB_DEVREQ_SET_DESCRIPTOR: status = handle_SET_DESCRIPTOR(hub, irp); break;
        case USB_DEVREQ_GET_CONFIGURATION: status = handle_GET_CONFIGURATION(hub, irp); break;
        case USB_DEVREQ_SET_CONFIGURATION: status = handle_SET_CONFIGURATION(hub, irp); break;
        default:
          die("unsupported bRequest in UHCI hub controller");
      }

      hub->dcp_irp_state = IRP_SETUP;
      break;
  }

  // Call the IRP's callback.
  // TODO(aoates): is it safe to do this synchronously?  Should we throw it onto
  // the shared USB threadpool?
  irp->callback(irp, irp->callback_arg);
  return status;
}

// Run in an interrupt context.  Checks for status changes and finishes the IRP
// if they exist.  Otherwise re-schedules the timer.
struct uhci_check_sc_timer_args {
  uhci_hub_t* hub;
  usb_hcdi_irp_t* irp;
};
typedef struct uhci_check_sc_timer_args uhci_check_sc_timer_args_t;
void uhci_check_sc_timer(void* arg) {
  uhci_check_sc_timer_args_t* args = (uhci_check_sc_timer_args_t*)arg;
  KASSERT(args->irp->status == USB_IRP_PENDING);
  KASSERT(args->hub->state == CONFIGURED);

  // TODO(aoates): check halted bit.
  uint8_t status_change = 0x0;
  const uint16_t port1_sc = ins(args->hub->hc->base_port + PORTSC1);
  const uint16_t port2_sc = ins(args->hub->hc->base_port + PORTSC2);

  // We don't currently register any hub-level status changes.
  if ((port1_sc & PORTSC_CONNECT_CHG) || (port1_sc & PORTSC_ENABLE_CHG) ||
      args->hub->c_port_reset[0] || args->hub->c_port_suspend[0]) {
    status_change |= 0x02;
  }

  if ((port2_sc & PORTSC_CONNECT_CHG) || (port2_sc & PORTSC_ENABLE_CHG) ||
      args->hub->c_port_reset[1] || args->hub->c_port_suspend[1]) {
    status_change |= 0x04;
  }

  if (status_change != 0x0) {
    if (args->irp->buflen > 0) {
      args->irp->out_len = 1;
      *(uint8_t*)args->irp->buffer = status_change;
    } else {
      args->irp->out_len = 0;
    }
    args->irp->status = USB_IRP_SUCCESS;
    kmemset(args, 0, sizeof(uhci_check_sc_timer_args_t));  // TODO(remove)
    kfree(args);
    args->irp->callback(args->irp, args->irp->callback_arg);
  } else {
    // "NACK" the packet and schedule a timer to run in 250ms to check again.
    register_event_timer(get_time_ms() + UHCI_HUB_STATUS_CHANGE_INTERVAL,
                         &uhci_check_sc_timer, args, 0x0);
  }
}

static int handle_sc_irp(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  uhci_check_sc_timer_args_t* args = (uhci_check_sc_timer_args_t*)
      kmalloc(sizeof(uhci_check_sc_timer_args_t));
  args->hub = hub;
  args->irp = irp;
  register_event_timer(get_time_ms() + UHCI_HUB_STATUS_CHANGE_INTERVAL,
                       &uhci_check_sc_timer, args, 0x0);
  return 0;
}

int uhci_hub_handle_irp(uhci_hub_t* hub, usb_hcdi_irp_t* irp) {
  KASSERT(hub->address == irp->endpoint->device->address);

  switch (irp->endpoint->endpoint_idx) {
    case USB_DEFAULT_CONTROL_PIPE:
      return handle_dcp_irp(hub, irp);

    case UHCI_HUB_STATUS_CHANGE:
      return handle_sc_irp(hub, irp);

    default:
      klogf("error: unknown endpoint %d in UHCI hub handler\n",
            irp->endpoint->endpoint_idx);
      die("unknown endpoint in UHCI hub handler");
  }

  return 0;
}
