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

  if (dev->bus->hcd->register_endpoint != 0x0) {
    dev->bus->hcd->register_endpoint(dev->bus->hcd, endpoint);
  }
  dev->endpoints[endpoint->endpoint_idx] = 0x0;
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
    klogf("USB ERROR: endpoint %d registered twice", endpoint_addr);
    die("double endpoint");
  }

  usb_endpoint_t* endpoint = (usb_endpoint_t*)kmalloc(sizeof(usb_endpoint_t));
  kmemset(endpoint, 0, sizeof(usb_endpoint_t));

  switch (endpoint_desc->bmAttributes &
          USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_MASK) {
    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_CONTROL:
      endpoint->type = USB_CONTROL;
      break;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_ISO:
      klogf("USB WARNING: isochronous endpoints unsupported\n");
      endpoint->type = USB_ISOCHRONOUS;
      break;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_BULK:
      endpoint->type = USB_BULK;
      break;

    case USB_DESC_ENDPOINT_BMATTR_TRANS_TYPE_INTERRUPT:
      endpoint->type = USB_INTERRUPT;
      break;

    default:
      klogf("invalid endpoint type: 0x%x\n", endpoint_desc->bmAttributes);
      die("invalid USB endpoint type");
  }

  endpoint->endpoint_idx = endpoint_addr;
  if (endpoint->type == USB_CONTROL) {
    endpoint->dir = USB_INVALID_DIR;
  } else {
    endpoint->dir =
        (endpoint_desc->bEndpointAddress & USB_DESC_ENDPOINT_DIR_IN) ?
        USB_IN : USB_OUT;
  }
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
      klogf("USB WARNING: only found %d (of %d) endpoints for interface %d\n",
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
        klogf("USB WARNING: found alternate setting for interface %d (%d); "
              "ignoring\n", iface->bInterfaceNumber, iface->bAlternateSetting);
      } else {
        interfaces_found++;
        usb_create_interface_endpoints(dev, node);
      }
    }
    node = node->next;
  }

  if (interfaces_found != config_desc->bNumInterfaces) {
    klogf("USB WARNING: found %d interfaces; expected %d\n",
          interfaces_found, config_desc->bNumInterfaces);
  }
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
    klogf("ERROR: USB device init failed; no free addresses on bus");
    usb_init_done(state);
    return;
  }

  klogf("INFO: USB assigning address %d to device %x\n",
        state->address, state->dev);

  state->request = usb_alloc_request();
  usb_make_SET_ADDRESS(state->request, state->address);

  // Set up the IRP.
  create_irp(&state->irp, state->dev, 0x0, 0, &usb_set_address_done, state);

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

  klogf("INFO: SET_ADDRESS for device %x successful\n", state->dev);

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

  klogf("INFO: USB getting device descriptor for device %x\n", state->dev);

  usb_make_GET_DESCRIPTOR(state->request,
                          USB_DESC_DEVICE, 0, sizeof(usb_desc_dev_t));

  // Set up the IRP.
  create_irp(&state->irp, state->dev, &state->dev->dev_desc,
             sizeof(usb_desc_dev_t), &usb_get_device_desc_done, state);

  int result = usb_send_request(&state->irp, state->request);
  if (result != 0) {
    klogf("ERROR: USB device init failed; usb_send_request returned %s",
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
    klogf("ERROR: USB device init failed; GET_DESCRIPTOR (device) IRP failed");
    usb_init_done(state);
    return;
  }
  // TODO(aoates): we shouldn't assert this, since the device may misbehave.
  KASSERT(irp->outlen == sizeof(usb_desc_dev_t));

  // TODO(aoates): process descriptor (e.g. max packet size, etc).

  klogf("INFO: USB read device descriptor for device %x:\n", state->dev);
  usb_print_desc_dev(&state->dev->dev_desc);

  KASSERT(state->dev->dev_desc.bNumConfigurations > 0);
  usb_get_config_desc(state);
}

static void usb_get_config_desc(usb_init_state_t* state) {
  const int kNumConfigs = state->dev->dev_desc.bNumConfigurations;

  KASSERT_DBG(state->dev->state == USB_DEV_ADDRESS);
  KASSERT_DBG(state->dev->address != USB_DEFAULT_ADDRESS);
  KASSERT(state->next_config_idx < kNumConfigs);

  klogf("INFO: USB getting config descriptor #%d for device %x\n",
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
    klogf("ERROR: USB device init failed; usb_send_request returned %s",
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
    klogf("ERROR: USB device init failed; GET_DESCRIPTOR (config) IRP failed");
    usb_init_done(state);
    return;
  }

  klogf("INFO: USB read %d bytes of config descriptor for device %x\n",
        state->irp.outlen, state->dev);

  KASSERT_DBG(state->dev->configs[state->next_config_idx].desc == 0x0);
  int result = usb_parse_descriptors(&state->dev->configs[state->next_config_idx],
                                     state->config_buffer, CONFIG_BUFFER_SIZE);
  KASSERT(result == 0);  // TODO(aoates): handle more gracefully.
  usb_print_desc_list(&state->dev->configs[state->next_config_idx]);

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
    klogf("USB: no driver found for device with class/subclass 0x%x/0x%x\n",
          (int)state->dev->dev_desc.bDeviceClass,
          (int)state->dev->dev_desc.bDeviceSubClass);
  } else {
    int result = driver->adopt_device(state->dev);
    if (result) {
      klogf("USB: Warning: unable to assign driver to device: %s\n",
            errorname(-result));
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
    klogf("ERROR: USB device init failed; usb_send_request returned %s",
          errorname(-result));
    // TODO(aoates): handle failures more gracefully.
    die("Unable to configure USB device");
  }
}

static void usb_set_configuration_done(usb_irp_t* irp, void* arg) {
  // TODO(aoates): handle failure more gracefully.
  KASSERT(irp->status == USB_IRP_SUCCESS);
  KASSERT_DBG(irp->outlen == 0);

  set_configuration_state_t* state = (set_configuration_state_t*)arg;
  usb_free_request(state->request);

  // Update the device's state.
  if (state->config == 0) {
    state->dev->state = USB_DEV_ADDRESS;

    // Remove any existing endpoints.
    // TODO(aoates): how do we guarantee that there are no outstanding refereces
    // to these endpoints?
    // TODO(aoates): ensure any pending IRPs on these endpoints are finished.
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
