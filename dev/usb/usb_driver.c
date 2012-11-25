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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/usb/bus.h"
#include "dev/usb/device.h"
#include "dev/usb/usb_driver.h"
#include "kmalloc.h"

void usb_add_endpoint(usb_device_t* dev, usb_endpoint_t* endpoint) {
  KASSERT(endpoint->endpoint_idx < USB_NUM_ENDPOINTS);
  KASSERT(dev->endpoints[endpoint->endpoint_idx] == 0x0);
  KASSERT(endpoint->device == 0x0);

  endpoint->device = dev;
  dev->endpoints[endpoint->endpoint_idx] = endpoint;

  endpoint->hcd_data = 0x0;
  if (dev->bus->hcd->register_endpoint != 0x0) {
    dev->bus->hcd->register_endpoint(dev->bus->hcd, endpoint);
  }
}

// Create a default control pipe endpoint for the given device.
static void usb_create_default_control_pipe(usb_device_t* dev) {
  usb_endpoint_t* defctrl = (usb_endpoint_t*)kmalloc(sizeof(usb_endpoint_t));
  kmemset(defctrl, 0, sizeof(usb_endpoint_t));

  defctrl->endpoint_idx = USB_DEFAULT_CONTROL_PIPE;
  defctrl->type = USB_CONTROL;
  defctrl->dir = USB_INVALID_DIR;
  defctrl->max_packet = USB_DEFAULT_MAX_PACKET;

  usb_add_endpoint(dev, defctrl);
}

usb_device_t* usb_create_device(usb_bus_t* bus, usb_device_t* parent,
                                usb_speed_t speed) {
  KASSERT(bus->default_address_in_use == 0);

  usb_device_t* dev = (usb_device_t*)kmalloc(sizeof(usb_device_t));
  kmemset(dev, 0, sizeof(usb_device_t));

  dev->bus = bus;
  dev->state = USB_DEV_INVALID;
  dev->address = USB_DEFAULT_ADDRESS;
  dev->speed = speed;

  dev->parent = parent;
  dev->first_child = 0x0;
  dev->next = 0x0;

  if (parent == 0x0) {
    // This is the root hub.
    KASSERT(bus->root_hub == 0x0);
    bus->root_hub = dev;
  } else {
    // Insert at the start of the parent's child list.
    KASSERT(bus->root_hub != 0x0);
    dev->next = parent->first_child;
    parent->first_child = dev;
  }

  // Set up the default control endpoint.
  usb_create_default_control_pipe(dev);

  bus->default_address_in_use = 1;
  return dev;
}

// Allocate and return a free address for the given bus.  Returns
// USB_DEFAULT_ADDRESS if no addresses are available.
uint8_t usb_get_free_address(usb_bus_t* bus) {
  if (bus->next_address == 255) {
    return USB_DEFAULT_ADDRESS;
  }
  return bus->next_address++;
}

// Tracks the state as we go through all the stages of usb_init_device().
struct usb_init_state {
  usb_device_t* dev;
  usb_irp_t irp;
  usb_dev_request_t* request;
  uint8_t address;
};
typedef struct usb_init_state usb_init_state_t;

// Different stages of usb_init_device.
static void usb_set_address(usb_init_state_t* state);
static void usb_set_address_done(usb_irp_t* irp, void* arg);
static void usb_get_device_desc(usb_init_state_t* state);
static void usb_init_done(usb_init_state_t* state);

void usb_init_device(usb_device_t* dev) {
  KASSERT(dev->state == USB_DEV_DEFAULT);
  KASSERT(dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(dev->bus->default_address_in_use);
}

static void usb_set_address(usb_init_state_t* state) {
  KASSERT(state->dev->state == USB_DEV_DEFAULT);
  KASSERT(state->dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(state->dev->bus->default_address_in_use);

  state->address = usb_get_free_address(state->dev->bus);
  if (state->address == USB_DEFAULT_ADDRESS) {
    klogf("ERROR: USB device init failed; no free addresses on bus");
    usb_init_done(state);
    return;
  }

  state->request = usb_alloc_request();
  state->request->bmRequestType =
      USB_DEVREQ_DIR_HOST2DEV |
      USB_DEVREQ_TYPE_STD |
      USB_DEVREQ_RCPT_DEV;
  KASSERT(state->request->bmRequestType == 0x0);
  state->request->bRequest = USB_DEVREQ_SET_ADDRESS;
  state->request->wValue = state->address;
  state->request->wIndex = state->request->wLength = 0;

  // Set up the IRP.
  usb_init_irp(&state->irp);
  state->irp.endpoint = state->dev->endpoints[USB_DEFAULT_CONTROL_PIPE];
  state->irp.buffer = 0x0;
  state->irp.buflen = 0;
  state->irp.callback = &usb_set_address_done;
  state->irp.cb_arg = state;

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    klogf("ERROR: USB device init failed; usb_send_request returned %s",
          errorname(-result));
    usb_init_done(state);
    return;
  }
}

static void usb_set_address_done(usb_irp_t* irp, void* arg) {
  usb_init_state_t* state = (usb_init_state_t*)arg;
  KASSERT(irp == &state->irp);

  // Check if IRP was successful.
  if (irp->status != USB_IRP_SUCCESS) {
    klogf("ERROR: USB device init failed; SET_ADDRESS IRP failed");
    usb_init_done(state);
    return;
  }
  KASSERT(irp->outlen == 0);

  KASSERT(state->dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(state->dev->bus->default_address_in_use);
  state->dev->address = state->address;
  state->dev->state = USB_DEV_ADDRESS;
  state->dev->bus->default_address_in_use = 0;
  // TODO(aoates): wake up waiting threads/callbacks for default address.

  // Get device descriptor.
  usb_get_device_desc(state);
}

static void usb_get_device_desc(usb_init_state_t* state) {
  KASSERT(state->dev->state == USB_DEV_ADDRESS);
  KASSERT(state->dev->address != USB_DEFAULT_ADDRESS);

  state->request->bmRequestType =
      USB_DEVREQ_DIR_DEV2HOST |
      USB_DEVREQ_TYPE_STD |
      USB_DEVREQ_RCPT_DEV;
  state->request->bRequest = USB_DEVREQ_GET_DESCRIPTOR;
  // Device descriptor in high byte, index 0 in low byte.
  state->request->wValue = USB_DESC_DEVICE << 8;
  state->request->wIndex = 0;
  state->request->wLength = sizeof(usb_desc_dev_t);

  // Set up the IRP.
  usb_init_irp(&state->irp);
  state->irp.endpoint = state->dev->endpoints[USB_DEFAULT_CONTROL_PIPE];
  state->irp.buffer = 0x0;  // TODO start here
  state->irp.buflen = 0;
  state->irp.callback = &usb_set_address_done;
  state->irp.cb_arg = state;

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    klogf("ERROR: USB device init failed; usb_send_request returned %s",
          errorname(-result));
    usb_init_done(state);
    return;
  }
}

static void usb_init_done(usb_init_state_t* state) {
  if (state->request != 0x0) {
    usb_free_request(state->request);
  }
  kmemset(state, 0, sizeof(usb_init_state_t));  // DBG
  kfree(state);
}
