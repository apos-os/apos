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

#include "dev/usb/drivers/hub/control.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "memory/kmalloc.h"
#include "common/math.h"
#include "dev/usb/bus.h"
#include "dev/usb/drivers/hub/request.h"
#include "dev/usb/request.h"

static void get_hub_desc_done(usb_irp_t* irp, void* arg);

typedef struct {
  usb_hubd_callback_t callback;
  usb_dev_request_t* request;
} context_t;

void usb_hubd_get_hub_descriptor(
    usb_device_t* dev, usb_hubd_desc_t* desc,
    usb_hubd_callback_t callback) {
  context_t* context = (context_t*)kmalloc(sizeof(context_t));

  usb_dev_request_t* request = usb_alloc_request();
  usb_make_GET_HUB_DESCRIPTOR(request, sizeof(usb_hubd_desc_t));

  usb_irp_t* irp = (usb_irp_t*)kmalloc(sizeof(usb_irp_t));
  usb_init_irp(irp);

  irp->endpoint = dev->endpoints[USB_DEFAULT_CONTROL_PIPE];

  irp->buffer = desc;
  irp->buflen = sizeof(usb_hubd_desc_t);

  irp->callback = &get_hub_desc_done;
  irp->cb_arg = context;

  context->request = request;
  context->callback = callback;

  int result = usb_send_request(irp, request);
  if (result) {
    klogf("USB HUBD: sending GET_DESCRIPTOR (hub) for hub %d.%d failed: %s\n",
          dev->bus->bus_index, dev->address, errorname(-result));
    kfree(context);
    kfree(irp);
    usb_free_request(request);
    callback(dev, result);
  }
}

static void get_hub_desc_done(usb_irp_t* irp, void* arg) {
  usb_device_t* dev = irp->endpoint->device;

  int result = 0;
  if (irp->status != USB_IRP_SUCCESS) {
    klogf("USB HUBD: failed to read hub descriptor for hub %d.%d\n",
          dev->bus->bus_index, dev->address);
    result = -EIO;
  }

  context_t* context = (context_t*)arg;
  usb_hubd_callback_t cb = context->callback;

  // Free the IRP, context and request.
  kfree(irp);
  usb_free_request(context->request);
  kfree(context);

  cb(dev, result);
}

static void get_port_status_done(usb_irp_t* irp, void* arg);

void usb_hubd_get_port_status(
    usb_device_t* dev, int port,
    uint16_t status_out[2], usb_hubd_callback_t callback) {
  KASSERT(port > 0);
  context_t* context = (context_t*)kmalloc(sizeof(context_t));

  usb_dev_request_t* request = usb_alloc_request();
  usb_make_GET_PORT_STATUS(request, port);

  usb_irp_t* irp = (usb_irp_t*)kmalloc(sizeof(usb_irp_t));
  usb_init_irp(irp);

  irp->endpoint = dev->endpoints[USB_DEFAULT_CONTROL_PIPE];

  irp->buffer = status_out;
  irp->buflen = 4;

  irp->callback = &get_port_status_done;
  irp->cb_arg = context;

  context->request = request;
  context->callback = callback;

  int result = usb_send_request(irp, request);
  if (result) {
    klogf("USB HUBD: GET_PORT_STATUS for hub %d.%d/port %d failed: %s\n",
          dev->bus->bus_index, dev->address, port, errorname(-result));
    kfree(context);
    kfree(irp);
    usb_free_request(request);
    callback(dev, result);
  }
}

static void get_port_status_done(usb_irp_t* irp, void* arg) {
  usb_device_t* dev = irp->endpoint->device;

  int result = 0;
  if (irp->status != USB_IRP_SUCCESS) {
    klogf("USB HUBD: failed to get port status for hub %d.%d\n",
          dev->bus->bus_index, dev->address);
    result = -EIO;
  }

  context_t* context = (context_t*)arg;
  usb_hubd_callback_t cb = context->callback;

  // Free the IRP, context and request.
  kfree(irp);
  usb_free_request(context->request);
  kfree(context);

  cb(dev, result);
}

static void status_change_irp_done(usb_irp_t* irp, void* arg);

void usb_hubd_get_status_change(usb_device_t* dev, uint8_t* sc_buf,
                                int num_ports, int sc_endpoint,
                                usb_hubd_callback_t callback) {
  usb_irp_t* irp = (usb_irp_t*)kmalloc(sizeof(usb_irp_t));
  usb_init_irp(irp);

  irp->endpoint = dev->endpoints[sc_endpoint];
  irp->buffer = sc_buf;
  // One bit for each port, and one for the hub.
  irp->buflen = ceiling_div(1 + num_ports, 8);

  irp->callback = &status_change_irp_done;
  irp->cb_arg = callback;

  int result = usb_send_data_in(irp);
  if (result) {
    klogf("USB HUBD: unable to start status change IRP: %s\n",
          errorname(-result));
    kfree(irp);
    callback(dev, result);
  }
}

static void status_change_irp_done(usb_irp_t* irp, void* arg) {
  usb_device_t* dev = irp->endpoint->device;

  int result = 0;
  if (irp->status != USB_IRP_SUCCESS) {
    klogf("USB HUBD: status change IRP for hub %d.%d failed: %d\n",
          dev->bus->bus_index, dev->address, irp->status);
    result = -EIO;
  }

  kfree(irp);
  ((usb_hubd_callback_t)arg)(dev, result);
}
