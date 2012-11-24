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

#include "common/debug.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/klog.h"
#include "dev/usb/bus.h"
#include "dev/usb/hcd.h"
#include "dev/usb/usb.h"
#include "kmalloc.h"
#include "proc/kthread_pool.h"
#include "slab_alloc.h"

#define USB_FIRST_ADDRESS 1

static int g_usb_initialized = 0;

// Dedicated USB thread pool.  Used to run all driver callbacks and background
// processes to keep them off the interrupt contexts.
#define USB_POOL_SIZE 4
static kthread_pool_t g_pool;

// Slab allocator for usb_hcdi_irp_t's.
#define SLAB_MAX_PAGES 10
static slab_alloc_t* g_hcdi_irp_alloc = 0x0;

static usb_hcdi_irp_t* alloc_hcdi_irp() {
  if (!g_hcdi_irp_alloc) {
    g_hcdi_irp_alloc = slab_alloc_create(
        sizeof(usb_hcdi_irp_t), SLAB_MAX_PAGES);
  }
  return (usb_hcdi_irp_t*)slab_alloc(g_hcdi_irp_alloc);
}

void usb_init() {
  KASSERT(g_usb_initialized == 0);

  // Initialize each bus we know about.
  for (int i = 0; i < usb_num_buses(); ++i) {
    usb_bus_t* bus = usb_get_bus(i);
    KASSERT(bus->hcd != 0x0);
    KASSERT(bus->root_hub == 0x0);

    bus->next_address = USB_FIRST_ADDRESS;

    // Create a usb_device_t for the root hub of the bus.
    usb_device_t* root_hub = (usb_device_t*)kmalloc(sizeof(usb_device_t));
    kmemset(root_hub, 0, sizeof(usb_device_t));

    root_hub->bus = bus;
    root_hub->address = USB_DEFAULT_ADDRESS;
    root_hub->parent = 0x0;
    root_hub->first_child = 0x0;
    root_hub->next = 0x0;

    bus->default_address_in_use = 1;

    // TODO(aoates): assign the root hub an address and hand to the HUBD.

    bus->root_hub = root_hub;
  }

  // Initialize the thread pool.
  int result = kthread_pool_init(&g_pool, USB_POOL_SIZE);
  KASSERT(result == 0);

  g_usb_initialized = 1;
}

int usb_is_initialized() {
  return g_usb_initialized;
}

void usb_init_irp(usb_irp_t* irp) {
  kmemset(irp, 0, sizeof(usb_irp_t));
  irp->status = USB_IRP_PENDING;
}

// The context of a request.
struct usb_request_context {
  usb_irp_t* irp;
  usb_dev_request_t* request;
  usb_hcdi_irp_t* hcdi_irp;

  // The next callback to run in handling the request.  This will be pushed onto
  // the USB thread pool by the trampoline function (which is called by the
  // HCD, possibly on an interrupt context).
  //
  // The argument is a usb_request_context_t*.
  void (*callback)(void*);
};
typedef struct usb_request_context usb_request_context_t;

// Trampoline function.  This is set as the callback for the HCD IRP, and is
// invoked on an interrupt context (or possibly synchronously from
// schedule_irp).  Trampolines the next callback onto the USB thread pool.
static void usb_request_trampoline(usb_hcdi_irp_t* irp, void* arg) {
  usb_request_context_t* context = (usb_request_context_t*)arg;
  int result = kthread_pool_push(&g_pool, context->callback, context);
  KASSERT(result == 0);
}

// Clean up a request, free the context, and maybe invoke the IRP's callback.
static void usb_request_finish(usb_request_context_t* context,
                               int do_callback) {
  slab_free(g_hcdi_irp_alloc, context->hcdi_irp);
  context->hcdi_irp = 0x0;
  usb_irp_t* irp = context->irp;

  if (ENABLE_KERNEL_SAFETY_NETS) {
    kmemset(context, 0, sizeof(usb_request_context_t));
  }
  kfree(context);

  if (do_callback) {
    irp->callback(irp, irp->cb_arg);
  }
}

// Callbacks for the two later stages of sending a request (DATA and STATUS).
// These should always be invoked on the USB thread pool.
static void usb_request_DATA(void* arg);
static void usb_request_STATUS(void* arg);
static void usb_request_DONE(void* arg);

static void usb_request_DATA(void* arg) {
  // KASSERT(invoked on g_pool)
  usb_request_context_t* context = (usb_request_context_t*)arg;

  // Check the status of the SETUP IRP.
  KASSERT(context->hcdi_irp->status != USB_IRP_PENDING);
  if (context->hcdi_irp->status != USB_IRP_SUCCESS) {
    context->irp->status = context->hcdi_irp->status;
    usb_request_finish(context, 1);
    return;
  }

  KASSERT(context->irp->buflen > 0);

  // SETUP succeeded, so create the DATA IRP.
  kmemset(context->hcdi_irp, 0, sizeof(usb_hcdi_irp_t));
  context->hcdi_irp->endpoint = context->irp->endpoint;
  context->hcdi_irp->buffer = context->irp->buffer;
  context->hcdi_irp->buflen = context->irp->buflen;
  const uint8_t dir = context->request->bmRequestType & USB_DEVREQ_DIR_MASK;
  KASSERT_DBG(dir == USB_DEVREQ_DIR_HOST2DEV ||
              dir == USB_DEVREQ_DIR_DEV2HOST);
  if (dir == USB_DEVREQ_DIR_HOST2DEV) {
    context->hcdi_irp->pid = USB_PID_OUT;
  } else {
    context->hcdi_irp->pid = USB_PID_IN;
  }
  context->hcdi_irp->data_toggle = USB_DATA_TOGGLE_NORMAL;

  // Set up the next stage to trampoline into usb_request_STATUS.
  context->hcdi_irp->callback = &usb_request_trampoline;
  context->hcdi_irp->callback_arg = context;
  context->callback = &usb_request_STATUS;

  usb_hcdi_t* hc = context->irp->endpoint->device->bus->hcd;
  const int result = hc->schedule_irp(hc, context->hcdi_irp);
  // TODO(aoates): handle this more gracefully.
  KASSERT(result == 0);
}

static void usb_request_STATUS(void* arg) {
  // KASSERT(invoked on g_pool)
  usb_request_context_t* context = (usb_request_context_t*)arg;

  // Check the status of the DATA IRP.
  KASSERT(context->hcdi_irp->status != USB_IRP_PENDING);
  if (context->hcdi_irp->status != USB_IRP_SUCCESS) {
    context->irp->status = context->hcdi_irp->status;
    usb_request_finish(context, 1);
    return;
  }

  // The overall IRP's outlen is equal to the DATA phase's outlen.
  // TODO(aoates): is this correct if we came straight from SETUP?
  context->irp->outlen = context->hcdi_irp->out_len;

  // DATA succeeded, so create the STATUS IRP.
  kmemset(context->hcdi_irp, 0, sizeof(usb_hcdi_irp_t));
  context->hcdi_irp->endpoint = context->irp->endpoint;
  context->hcdi_irp->buffer = 0x0;
  context->hcdi_irp->buflen = 0;

  // Opposite direction from the DATA phase, and always DATA1.
  const uint8_t dir = context->request->bmRequestType & USB_DEVREQ_DIR_MASK;
  if (context->irp->buflen == 0 || dir == USB_DEVREQ_DIR_HOST2DEV) {
    context->hcdi_irp->pid = USB_PID_IN;
  } else {
    context->hcdi_irp->pid = USB_PID_OUT;
  }
  context->hcdi_irp->data_toggle = USB_DATA_TOGGLE_RESET1;

  // Set up the next stage to trampoline into usb_request_DONE.
  context->hcdi_irp->callback = &usb_request_trampoline;
  context->hcdi_irp->callback_arg = context;
  context->callback = &usb_request_DONE;

  usb_hcdi_t* hc = context->irp->endpoint->device->bus->hcd;
  const int result = hc->schedule_irp(hc, context->hcdi_irp);
  // TODO(aoates): handle this more gracefully.
  KASSERT(result == 0);
}

static void usb_request_DONE(void* arg) {
  // KASSERT(invoked on g_pool)
  usb_request_context_t* context = (usb_request_context_t*)arg;

  // Check the status of the STATUS IRP.
  KASSERT(context->hcdi_irp->status != USB_IRP_PENDING);
  if (context->hcdi_irp->status != USB_IRP_SUCCESS) {
    context->irp->status = USB_IRP_DEVICE_ERROR;
  } else {
    context->irp->status = USB_IRP_SUCCESS;
  }

  usb_request_finish(context, 1);
  return;
}

int usb_send_request(usb_irp_t* irp, usb_dev_request_t* request) {
  if (irp->endpoint->type != USB_CONTROL) {
    return -EINVAL;
  }

  irp->status = USB_IRP_PENDING;
  irp->outlen = 0;

  // TODO(aoates): should we use a slab allocator for these?
  usb_request_context_t* context =
      (usb_request_context_t*)kmalloc(sizeof(usb_request_context_t));
  context->irp = irp;
  context->request = request;

  // First send the SETUP packet.
  context->hcdi_irp = alloc_hcdi_irp();
  context->hcdi_irp->endpoint = irp->endpoint;
  context->hcdi_irp->buffer = request;
  context->hcdi_irp->buflen = sizeof(usb_dev_request_t);
  context->hcdi_irp->pid = USB_PID_SETUP;
  context->hcdi_irp->data_toggle = USB_DATA_TOGGLE_RESET0;

  // Set up the next stage to trampoline into usb_request_DATA,
  // usb_request_STATUS if there's no data to send/receive.
  context->hcdi_irp->callback = &usb_request_trampoline;
  if (context->irp->buflen > 0) {
    context->hcdi_irp->callback_arg = context;
    context->callback = &usb_request_DATA;
  } else {
    context->hcdi_irp->callback_arg = context;
    context->callback = &usb_request_STATUS;
  }

  usb_hcdi_t* hc = irp->endpoint->device->bus->hcd;
  const int result = hc->schedule_irp(hc, context->hcdi_irp);
  if (result != 0) {
    usb_request_finish(context, 0 /* don't run callback */);
  }
  return result;
}

int usb_send_data_in(usb_irp_t* irp) {
  // TODO
  die("usb_send_data_in NOT YET IMPLEMENTED");
  return -ENOTSUP;
}

int usb_send_data_out(usb_irp_t* irp) {
  // TODO
  die("usb_send_data_out NOT YET IMPLEMENTED");
  return -ENOTSUP;
}
