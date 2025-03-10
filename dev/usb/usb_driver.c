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
#include "dev/usb/drivers/drivers.h"
#include "dev/usb/usb_driver.h"
#include "memory/kmalloc.h"

#define KLOG(...) klogfm(KL_USB, __VA_ARGS__)

#define CONFIG_BUFFER_SIZE 512

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

void usb_remove_endpoint(usb_endpoint_t* endpoint) {
  usb_device_t* dev = endpoint->device;

  KASSERT(endpoint->endpoint_idx < USB_NUM_ENDPOINTS);
  KASSERT(dev->endpoints[endpoint->endpoint_idx] == endpoint);

  dev->endpoints[endpoint->endpoint_idx] = 0x0;

  usb_cancel_endpoint_irp(endpoint);

  if (dev->bus->hcd->unregister_endpoint != 0x0) {
    dev->bus->hcd->unregister_endpoint(dev->bus->hcd, endpoint);
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

// Create an endpoint in the given device given its descriptor.
static void usb_create_endpoint(usb_device_t* dev,
                                usb_desc_endpoint_t* endpoint_desc) {
  KASSERT_DBG(endpoint_desc->bDescriptorType == USB_DESC_ENDPOINT);

  // TODO(aoates): we shouldn't die on bad device configs.
  int endpoint_addr = endpoint_desc->bEndpointAddress & 0x0F;
  KASSERT(endpoint_addr > 0 && endpoint_addr < USB_NUM_ENDPOINTS);
  if (dev->endpoints[endpoint_addr] != 0x0) {
    KLOG(ERROR, "USB: endpoint %d registered twice", endpoint_addr);
    die("double endpoint");
  }

  usb_endpoint_t* endpoint = (usb_endpoint_t*)kmalloc(sizeof(usb_endpoint_t));
  kmemset(endpoint, 0, sizeof(usb_endpoint_t));

  endpoint->type = usb_desc_endpoint_type(endpoint_desc);
  if (endpoint->type == USB_INVALID_TTYPE) {
      KLOG(ERROR, "invalid endpoint type: 0x%x\n", endpoint_desc->bmAttributes);
      die("invalid USB endpoint type");
  }

  endpoint->endpoint_idx = endpoint_addr;
  endpoint->dir = usb_desc_endpoint_dir(endpoint_desc);
  endpoint->period = endpoint_desc->bInterval;
  endpoint->max_packet =
      endpoint_desc->wMaxPacketSize & USB_DESC_ENDPOINT_MAX_PACKET_SIZE_MASK;
  endpoint->data_toggle = USB_DATA0;

  usb_add_endpoint(dev, endpoint);
}

// Given an interface descriptor, create all the necessary endpoints.
static void usb_create_interface_endpoints(
    usb_device_t* dev, usb_desc_list_node_t* interface_node) {
  usb_desc_interface_t* iface = (usb_desc_interface_t*)interface_node->desc;
  KASSERT_DBG(iface->bDescriptorType == USB_DESC_INTERFACE);

  // Look for each endpoint.
  usb_desc_list_node_t* node = interface_node->next;
  int endpoint = 0;
  while (endpoint < iface->bNumEndpoints) {
    if (!node || node->desc->bDescriptorType == USB_DESC_CONFIGURATION ||
        node->desc->bDescriptorType == USB_DESC_INTERFACE) {
      KLOG(WARNING, "USB: only found %d (of %d) endpoints for interface %d\n",
           endpoint, iface->bNumEndpoints, iface->bInterfaceNumber);
      return;
    }

    if (node->desc->bDescriptorType == USB_DESC_ENDPOINT) {
      usb_desc_endpoint_t* endpoint_desc = (usb_desc_endpoint_t*)node->desc;
      usb_create_endpoint(dev, endpoint_desc);
      endpoint++;
    }

    node = node->next;
  }
}

// Create the appropriate endpoints for the given device and configuration.
static void usb_create_config_endpoints(usb_device_t* dev, int config_idx) {
  // First find the requested config descriptor.
  int config_desc_idx = -1;
  usb_desc_config_t* config_desc = 0x0;
  for (int i = 0; i < dev->dev_desc.bNumConfigurations; ++i) {
    config_desc = (usb_desc_config_t*)dev->configs[i].desc;
    KASSERT(config_desc->bDescriptorType == USB_DESC_CONFIGURATION);
    if (config_desc->bConfigurationValue == config_idx) {
      config_desc_idx = i;
      break;
    }
  }
  KASSERT(config_desc_idx >= 0);  // TODO(aoates): shouldn't die on invalid descs

  // For each interface in the given configuration, create the appropriate
  // endpoints.
  int interfaces_found = 0;
  usb_desc_list_node_t* node = dev->configs[config_desc_idx].next;
  while (node != 0x0) {
    // TODO(aoates): support alternate interfaces, and select the appropriate
    // alternate interface here.
    if (node->desc->bDescriptorType == USB_DESC_INTERFACE) {
      usb_desc_interface_t* iface = (usb_desc_interface_t*)node->desc;
      if (iface->bAlternateSetting != 0) {
        KLOG(WARNING, "USB: found alternate setting for interface %d (%d); "
             "ignoring\n", iface->bInterfaceNumber, iface->bAlternateSetting);
      } else {
        interfaces_found++;
        usb_create_interface_endpoints(dev, node);
      }
    }
    node = node->next;
  }

  if (interfaces_found != config_desc->bNumInterfaces) {
    KLOG(WARNING, "USB: found %d interfaces; expected %d\n",
         interfaces_found, config_desc->bNumInterfaces);
  }
}

typedef struct {
  void (*callback)(usb_bus_t* bus, void* arg);
  void* arg;
  list_link_t link;
} pending_closure_t;

void usb_acquire_default_address(usb_bus_t* bus,
                                 void (*callback)(usb_bus_t* bus, void* arg),
                                 void* arg) {
  if (bus->default_address_in_use) {
    pending_closure_t* closure = (pending_closure_t*)kmalloc(sizeof(pending_closure_t));
    closure->callback = callback;
    closure->arg = arg;
    closure->link = LIST_LINK_INIT;
    list_push(&bus->queued_address_callbacks, &closure->link);
  } else {
    bus->default_address_in_use = 1;
    callback(bus, arg);
  }
}

void usb_release_default_address(usb_bus_t* bus) {
  KASSERT(bus->default_address_in_use == 1);

  if (list_empty(&bus->queued_address_callbacks)) {
    bus->default_address_in_use = 0;
  } else {
    list_link_t* link = list_pop(&bus->queued_address_callbacks);
    pending_closure_t* closure = container_of(link, pending_closure_t, link);
    closure->callback(bus, closure->arg);
    kfree(closure);
  }
}

usb_device_t* usb_create_device(usb_bus_t* bus, usb_device_t* parent, int port,
                                usb_speed_t speed) {
  KASSERT(bus->default_address_in_use == 1);
  usb_device_t* dev = (usb_device_t*)kmalloc(sizeof(usb_device_t));
  kmemset(dev, 0, sizeof(usb_device_t));

  dev->bus = bus;
  dev->state = USB_DEV_INVALID;
  dev->address = USB_DEFAULT_ADDRESS;
  dev->speed = speed;

  dev->parent = parent;
  dev->port = port;
  dev->first_child = 0x0;
  dev->next = 0x0;
  dev->driver = 0x0;
  dev->driver_data = 0x0;

  if (parent == 0x0) {
    // This is the root hub.
    KASSERT(bus->root_hub == 0x0);
    bus->root_hub = dev;
  } else {
    // Insert it in the parent's child list in order of port number.
    KASSERT(bus->root_hub != 0x0);
    dev->next = 0x0;
    usb_device_t* prev = 0x0, *cur = parent->first_child;
    while (cur && cur->port < port) {
      prev = cur;
      cur = cur->next;
    }
    if (cur && cur->port == port) {
      KLOG(ERROR, "USB: multiple devices on hub %d.%d port %d\n",
           parent->bus->bus_index, parent->address, port);
    }
    dev->next = cur;
    if (prev) {
      prev->next = dev;
    } else {
      parent->first_child = dev;
    }
  }

  // Set up the default control endpoint.
  usb_create_default_control_pipe(dev);

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

static void create_irp(usb_irp_t* irp, usb_device_t* dev, void* buffer,
                       int buflen, void (*callback)(struct usb_irp*, void*),
                       void* arg) {
  usb_init_irp(irp);
  irp->endpoint = dev->endpoints[USB_DEFAULT_CONTROL_PIPE];
  irp->buffer = buffer;
  irp->buflen = buflen;
  irp->callback = callback;
  irp->cb_arg = arg;
}

// Tracks the state as we go through all the stages of usb_init_device().
struct usb_init_state {
  usb_device_t* dev;
  usb_irp_t irp;
  usb_dev_request_t* request;
  uint8_t address;
  uint8_t next_config_idx;  // The next configuration desc to load.
  void* config_buffer;
};
typedef struct usb_init_state usb_init_state_t;

// Different stages of usb_init_device.
static void usb_set_address(usb_init_state_t* state);
static void usb_set_address_done(usb_irp_t* irp, void* arg);
static void usb_get_device_desc(usb_init_state_t* state);
static void usb_get_device_desc_done(usb_irp_t* irp, void* arg);
static void usb_get_config_desc(usb_init_state_t* state);
static void usb_get_config_desc_done(usb_irp_t* irp, void* arg);
static void usb_init_driver(usb_init_state_t* state);
static void usb_init_done(usb_init_state_t* state);

void usb_init_device(usb_device_t* dev) {
  KASSERT(dev->state == USB_DEV_DEFAULT);
  KASSERT(dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(dev->bus->default_address_in_use);

  usb_init_state_t* state =
      (usb_init_state_t*)kmalloc(sizeof(usb_init_state_t));
  kmemset(state, 0, sizeof(usb_init_state_t));
  state->dev = dev;

  usb_set_address(state);
}

static void usb_set_address(usb_init_state_t* state) {
  KASSERT(state->dev->state == USB_DEV_DEFAULT);
  KASSERT(state->dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(state->dev->bus->default_address_in_use);

  state->address = usb_get_free_address(state->dev->bus);
  if (state->address == USB_DEFAULT_ADDRESS) {
    KLOG(WARNING, "USB device init failed; no free addresses on bus");
    usb_init_done(state);
    return;
  }

  KLOG(DEBUG, "USB assigning address %d to device %p\n",
       state->address, state->dev);

  state->request = usb_alloc_request();
  usb_make_SET_ADDRESS(state->request, state->address);

  // Set up the IRP.
  create_irp(&state->irp, state->dev, 0x0, 0, &usb_set_address_done, state);

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    KLOG(WARNING, "USB device init failed; usb_send_request returned %s",
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
    // TODO(aoates): are there any circumstances in which the IRP would fail,
    // but the device would remain in the DEFAULT state?  In that case, it's
    // invalid for us to release the default address without somehow disabling
    // the device first.
    KLOG(WARNING, "USB device init failed; SET_ADDRESS IRP failed");
    state->dev->state = USB_DEV_INVALID;
    usb_release_default_address(state->dev->bus);
    usb_init_done(state);
    return;
  }
  KASSERT(irp->outlen == 0);

  KLOG(DEBUG, "SET_ADDRESS for device %p successful\n", state->dev);

  KASSERT(state->dev->address == USB_DEFAULT_ADDRESS);
  KASSERT(state->dev->bus->default_address_in_use);
  state->dev->address = state->address;
  state->dev->state = USB_DEV_ADDRESS;
  usb_release_default_address(state->dev->bus);

  // Get device descriptor.
  usb_get_device_desc(state);
}

static void usb_get_device_desc(usb_init_state_t* state) {
  KASSERT(state->dev->state == USB_DEV_ADDRESS);
  KASSERT(state->dev->address != USB_DEFAULT_ADDRESS);

  KLOG(DEBUG, "USB getting device descriptor for device %p\n", state->dev);

  usb_make_GET_DESCRIPTOR(state->request,
                          USB_DESC_DEVICE, 0, sizeof(usb_desc_dev_t));

  // Set up the IRP.
  create_irp(&state->irp, state->dev, &state->dev->dev_desc,
             sizeof(usb_desc_dev_t), &usb_get_device_desc_done, state);

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    KLOG(WARNING, "USB device init failed; usb_send_request returned %s",
         errorname(-result));
    usb_init_done(state);
    return;
  }
}

static void usb_get_device_desc_done(usb_irp_t* irp, void* arg) {
  usb_init_state_t* state = (usb_init_state_t*)arg;
  KASSERT(irp == &state->irp);

  // Check if IRP was successful.
  if (irp->status != USB_IRP_SUCCESS) {
    KLOG(WARNING, "USB device init failed; GET_DESCRIPTOR (device) IRP failed");
    usb_init_done(state);
    return;
  }
  // TODO(aoates): we shouldn't assert this, since the device may misbehave.
  KASSERT(irp->outlen == sizeof(usb_desc_dev_t));

  // TODO(aoates): process descriptor (e.g. max packet size, etc).

  KLOG(DEBUG2, "USB read device descriptor for device %p:\n", state->dev);
  usb_print_desc_dev(DEBUG2, &state->dev->dev_desc);

  KASSERT(state->dev->dev_desc.bNumConfigurations > 0);
  usb_get_config_desc(state);
}

static void usb_get_config_desc(usb_init_state_t* state) {
  const int kNumConfigs = state->dev->dev_desc.bNumConfigurations;

  KASSERT_DBG(state->dev->state == USB_DEV_ADDRESS);
  KASSERT_DBG(state->dev->address != USB_DEFAULT_ADDRESS);
  KASSERT(state->next_config_idx < kNumConfigs);

  KLOG(DEBUG, "USB getting config descriptor #%d for device %p\n",
       state->next_config_idx, state->dev);

  // If it doesn't already exist, allocate the configuration descriptor array.
  if (state->dev->configs == 0x0) {
    const int size = sizeof(usb_desc_list_node_t) * kNumConfigs;
    state->dev->configs = (usb_desc_list_node_t*)kmalloc(size);
    kmemset(state->dev->configs, 0, size);
  }

  // ...and a buffer.
  if (state->config_buffer == 0x0) {
    state->config_buffer = kmalloc(CONFIG_BUFFER_SIZE);
    KASSERT(state->config_buffer != 0x0); // TODO(aoates): better handling.
  }

  usb_make_GET_DESCRIPTOR(state->request,
                          USB_DESC_CONFIGURATION, state->next_config_idx, CONFIG_BUFFER_SIZE);
  create_irp(&state->irp, state->dev, state->config_buffer, CONFIG_BUFFER_SIZE,
                  &usb_get_config_desc_done, state);

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    KLOG(WARNING, "USB device init failed; usb_send_request returned %s",
         errorname(-result));
    usb_init_done(state);
    return;
  }

}

static void usb_get_config_desc_done(usb_irp_t* irp, void* arg) {
  usb_init_state_t* state = (usb_init_state_t*)arg;
  KASSERT(irp == &state->irp);
  KASSERT_DBG(state->next_config_idx < state->dev->dev_desc.bNumConfigurations);

  // Check if IRP was successful.
  if (irp->status != USB_IRP_SUCCESS) {
    KLOG(WARNING, "USB device init failed; GET_DESCRIPTOR (config) IRP failed "
         "(config idx: %d  IRP status: %d)\n", state->next_config_idx,
         irp->status);
    usb_init_done(state);
    return;
  }

  KLOG(DEBUG, "USB read %d bytes of config descriptor for device %p\n",
       state->irp.outlen, state->dev);

  KASSERT_DBG(state->dev->configs[state->next_config_idx].desc == 0x0);
  int result = usb_parse_descriptors(&state->dev->configs[state->next_config_idx],
                                     state->config_buffer, CONFIG_BUFFER_SIZE);
  KASSERT(result == 0);  // TODO(aoates): handle more gracefully.
  usb_print_desc_list(DEBUG2, &state->dev->configs[state->next_config_idx]);

  state->next_config_idx++;
  if (state->next_config_idx < state->dev->dev_desc.bNumConfigurations) {
    usb_get_config_desc(state);
    return;
  }

  usb_init_driver(state);
}

static void usb_init_driver(usb_init_state_t* state) {
  usb_driver_t* driver = usb_find_driver(state->dev);
  if (!driver) {
    KLOG(INFO, "USB: no driver found for device with class/subclass "
         "0x%x/0x%x\n", (int)state->dev->dev_desc.bDeviceClass,
         (int)state->dev->dev_desc.bDeviceSubClass);
  } else {
    int result = driver->adopt_device(state->dev);
    if (result) {
      KLOG(WARNING, "USB: unable to assign driver to device: %s\n",
           errorname(-result));
    } else {
      state->dev->driver = driver;
    }
  }

  // TODO finish init, etc
  usb_init_done(state);
}

static void usb_init_done(usb_init_state_t* state) {
  if (state->request != 0x0) {
    usb_free_request(state->request);
  }
  if (state->config_buffer != 0x0) {
    kfree(state->config_buffer);
  }
  kmemset(state, 0, sizeof(usb_init_state_t));  // DBG
  kfree(state);
}

void usb_detach_device(usb_device_t* dev) {
  // First, detach and delete all its children if it's a hub.
  while (dev->first_child) {
    usb_device_t* child = dev->first_child;
    usb_detach_device(child);
    usb_delete_device(child);
  }

  KLOG(DEBUG, "USB: detaching device %d.%d (from hub %d.%d/port %d)\n",
       dev->bus->bus_index, dev->address,
       dev->parent ? dev->parent->bus->bus_index : -1,
       dev->parent ? dev->parent->address : -1,
       dev->port);

  dev->state = USB_DEV_INVALID;

  // Clean up and remove all the endpoints (including the DCP).
  for (int i = 0; i < USB_NUM_ENDPOINTS; i++) {
    if (dev->endpoints[i]) {
      usb_endpoint_t* endpoint = dev->endpoints[i];
      usb_remove_endpoint(endpoint);
      kfree(endpoint);
    }
  }

  if (dev->driver) {
    dev->driver->cleanup_device(dev);
  }

  // Remove it from the device tree.
  if (!dev->parent) {
    KASSERT_DBG(dev->bus->root_hub == dev);
    KLOG(WARNING, "USB: removing the root hub device for bus %d\n",
         dev->bus->bus_index);
  } else {
    if (dev->parent->first_child == dev) {
      dev->parent->first_child = dev->next;
    } else {
      usb_device_t* prev = dev->parent->first_child;
      while (prev && prev->next != dev) {
        prev = prev->next;
      }
      // We must be in the list.
      KASSERT(prev != 0x0);

      prev->next = dev->next;
    }
    dev->next = 0x0;
    dev->parent = 0x0;
  }
}

void usb_delete_device(usb_device_t* dev) {
  KASSERT_DBG(dev->state == USB_DEV_INVALID);
  KASSERT_DBG(dev->parent == 0x0);
  KASSERT_DBG(dev->next == 0x0);
  KASSERT_DBG(dev->first_child == 0x0);

  for (int i = 0; i < USB_NUM_ENDPOINTS; ++i) {
    KASSERT_DBG(dev->endpoints[i] == 0x0);
  }

  if (dev->configs) {
    for (int i = 0; i < dev->dev_desc.bNumConfigurations; ++i) {
      if (dev->configs[i].desc) {
        kfree(dev->configs[i].desc);
      }
      usb_desc_list_node_t* cur = dev->configs[i].next;
      while (cur) {
        usb_desc_list_node_t* next = cur->next;
        kfree(cur->desc);
        kfree(cur);
        cur = next;
      }
    }
    kfree(dev->configs);
  }

  kfree(dev);
}

typedef struct {
  usb_device_t* dev;
  uint8_t config;
  void (*callback)(usb_device_t*, void*);
  void* arg;

  usb_dev_request_t* request;
  usb_irp_t irp;
} set_configuration_state_t;

static void usb_set_configuration_done(usb_irp_t* irp, void* arg);

void usb_set_configuration(usb_device_t* dev, uint8_t config,
                           void (*callback)(usb_device_t*, void*),
                           void* arg) {
  KASSERT(dev->state == USB_DEV_ADDRESS || dev->state == USB_DEV_CONFIGURED ||
          dev->state == USB_DEV_SUSPENDED);

  // TODO(aoates): should we check that the requested config is value?

  set_configuration_state_t* state =
      (set_configuration_state_t*)kmalloc(sizeof(set_configuration_state_t));
  state->dev = dev;
  state->config = config;
  state->callback = callback;
  state->arg = arg;

  state->request = usb_alloc_request();
  usb_make_SET_CONFIGURATION(state->request, config);

  // Set up the IRP.
  create_irp(&state->irp, state->dev, 0x0, 0, &usb_set_configuration_done,
             state);

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    KLOG(WARNING, "USB device init failed; usb_send_request returned %s",
         errorname(-result));
    // TODO(aoates): handle failures more gracefully.
    die("Unable to configure USB device");
  }
}

static void usb_set_configuration_done(usb_irp_t* irp, void* arg) {
  KASSERT_DBG(irp->outlen == 0);

  set_configuration_state_t* state = (set_configuration_state_t*)arg;
  usb_free_request(state->request);

  if (irp->status != USB_IRP_SUCCESS) {
    // TODO(aoates): if the device is currently configured, does this always
    // invalidate that?  Should we tear down all its endpoints and put it back
    // in the ADDRESS state?
    KLOG(INFO, "USB: SET_CONFIGURATION for device %d.%d failed (status %d)\n",
         state->dev->bus->bus_index, state->dev->address, irp->status);
    state->callback(state->dev, state->arg);
    kfree(state);
    return;
  }

  // Update the device's state.
  if (state->config == 0) {
    state->dev->state = USB_DEV_ADDRESS;

    // Remove any existing endpoints.
    for (int i = 1; i < USB_NUM_ENDPOINTS; i++) {
      if (state->dev->endpoints[i]) {
        usb_endpoint_t* endpoint = state->dev->endpoints[i];
        usb_remove_endpoint(endpoint);
        kfree(endpoint);
      }
    }
  } else {
    state->dev->state = USB_DEV_CONFIGURED;

    usb_create_config_endpoints(state->dev, state->config);

    for (int i = 0; i < USB_NUM_ENDPOINTS; i++) {
      if (state->dev->endpoints[i]) {
        state->dev->endpoints[i]->data_toggle = USB_DATA0;
      }
    }
  }

  state->callback(state->dev, state->arg);

  kfree(state);
}

void usb_get_configuration_values(usb_device_t* dev, uint8_t* config_values)  {
  for (int i = 0; i < dev->dev_desc.bNumConfigurations; ++i) {
    usb_desc_config_t* config = (usb_desc_config_t*)dev->configs[i].desc;
    KASSERT_DBG(config->bDescriptorType == USB_DESC_CONFIGURATION);
    config_values[i] = config->bConfigurationValue;
  }
}

usb_desc_list_node_t* usb_get_configuration_desc(usb_device_t* dev,
                                                 int config_value) {
  for (int i = 0; i < dev->dev_desc.bNumConfigurations; ++i) {
    usb_desc_config_t* config = (usb_desc_config_t*)dev->configs[i].desc;
    KASSERT_DBG(config->bDescriptorType == USB_DESC_CONFIGURATION);
    if (config->bConfigurationValue == config_value) {
      return &dev->configs[i];
    }
  }

  return 0x0;
}

usb_desc_list_node_t* usb_get_interface_desc(usb_device_t* dev,
                                             int config_value,
                                             int interface_index) {
  // First find a matching configuration.
  usb_desc_list_node_t* config_node =
      usb_get_configuration_desc(dev, config_value);
  if (!config_node) return 0x0;

  usb_desc_config_t* config = (usb_desc_config_t*)config_node->desc;

  // Now find the corresponding interface.
  if (interface_index < 0 || interface_index >= config->bNumInterfaces)
    return 0x0;

  usb_desc_list_node_t* node = config_node->next;
  while (node) {
    if (node->desc->bDescriptorType == USB_DESC_INTERFACE) {
      usb_desc_interface_t* interface = (usb_desc_interface_t*)node->desc;
      // Interfaces have zero-indexed numbers; they *should* be in order, but we
      // compare against the index descriptor just in case.
      if (interface->bInterfaceNumber == interface_index) {
        return node;
      }
    }
    node = node->next;
  }

  KLOG(INFO, "USB device %d.%d/config %d advertises %d interfaces, but "
       "the interface %d descriptor wasn't found\n",
       dev->bus->bus_index, dev->address, config_value,
       config->bNumInterfaces, interface_index);
  return 0x0;
}

usb_desc_list_node_t* usb_get_endpoint_desc(usb_device_t* dev,
                                             int config_value,
                                             int interface_index,
                                             int endpoint_index) {
  // First find a matching interface.
  usb_desc_list_node_t* interface_node =
      usb_get_interface_desc(dev, config_value, interface_index);
  if (!interface_node) return 0x0;

  KASSERT_DBG(interface_node->desc->bDescriptorType == USB_DESC_INTERFACE);
  usb_desc_interface_t* interface = (usb_desc_interface_t*)interface_node->desc;

  // Now find the corresponding endpoint.
  if (endpoint_index < 0 || endpoint_index >= interface->bNumEndpoints)
    return 0x0;

  usb_desc_list_node_t* node = interface_node->next;
  int cendpoint = 0;
  while (node) {
    if (node->desc->bDescriptorType == USB_DESC_INTERFACE) {
      break;
    }

    if (node->desc->bDescriptorType == USB_DESC_ENDPOINT) {
      if (cendpoint == endpoint_index) {
        return node;
      }
      cendpoint++;
    }
    node = node->next;
  }

  KLOG(INFO, "USB device %d.%d/config %d/iface %d advertises %d endpoints, but "
       "the endpoint %d descriptor wasn't found\n",
       dev->bus->bus_index, dev->address, config_value,
       interface_index, interface->bNumEndpoints, endpoint_index);
  return 0x0;
}
