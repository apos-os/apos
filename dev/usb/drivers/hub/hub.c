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

#include "dev/usb/drivers/hub/hub.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "dev/usb/drivers/hub/control.h"
#include "dev/usb/drivers/hub/request.h"
#include "dev/usb/usb_driver.h"
#include "memory/kmalloc.h"
#include "util/flag_printf.h"

#define KLOG(...) klogfm(KL_USB_HUB, __VA_ARGS__)

flag_spec_t PORT_STATUS_FLAGS[] = {
  FLAG_SPEC_FLAG("PORT_CONNECTION", USB_HUBD_PORT_CONNECTION),
  FLAG_SPEC_FLAG("PORT_ENABLE", USB_HUBD_PORT_ENABLE),
  FLAG_SPEC_FLAG("PORT_SUSPEND", USB_HUBD_PORT_SUSPEND),
  FLAG_SPEC_FLAG("PORT_OVER_CURRENT", USB_HUBD_PORT_OVER_CURRENT),
  FLAG_SPEC_FLAG("PORT_RESET", USB_HUBD_PORT_RESET),
  FLAG_SPEC_FLAG("PORT_POWER", USB_HUBD_PORT_POWER),
  FLAG_SPEC_FLAG("PORT_LOW_SPEED", USB_HUBD_PORT_LOW_SPEED),
  FLAG_SPEC_FLAG("PORT_HIGH_SPEED", USB_HUBD_PORT_HIGH_SPEED),
  FLAG_SPEC_FLAG("PORT_TEST", USB_HUBD_PORT_TEST),
  FLAG_SPEC_FLAG("PORT_INDICATOR", USB_HUBD_PORT_INDICATOR),
  FLAG_SPEC_END,
};

flag_spec_t PORT_CHANGE_FLAGS[] = {
  FLAG_SPEC_FLAG("C_PORT_CONNECTION", USB_HUBD_C_PORT_CONNECTION),
  FLAG_SPEC_FLAG("C_PORT_ENABLE", USB_HUBD_C_PORT_ENABLE),
  FLAG_SPEC_FLAG("C_PORT_SUSPEND", USB_HUBD_C_PORT_SUSPEND),
  FLAG_SPEC_FLAG("C_PORT_OVER_CURRENT", USB_HUBD_C_PORT_OVER_CURRENT),
  FLAG_SPEC_FLAG("C_PORT_RESET", USB_HUBD_C_PORT_RESET),
  FLAG_SPEC_END,
};

static void usb_print_desc_hub(klog_level_t level, usb_hubd_desc_t* desc) {
  KASSERT_DBG(desc->bDescriptorType == USB_HUBD_DESC_TYPE);
  KLOG(level, "  bDescLength: %d\n", desc->bLength);
  KLOG(level, "  bDescriptorType: HUB (%d)\n", desc->bDescriptorType);
  KLOG(level, "  bNbrPorts: %d\n", desc->bNbrPorts);
  KLOG(level, "  wHubCharacteristics: 0x%x\n", desc->wHubCharacteristics);
  KLOG(level, "  bPwrOn2PwrGood: %d\n", desc->bPwrOn2PwrGood);
  KLOG(level, "  bHubContrCurrent: %d\n", desc->bHubContrCurrent);

  KLOG(level, "  PortBits:");
  const int num_port_bits = 2 * ceiling_div(desc->bNbrPorts, 8);
  for (int i = 0; i < num_port_bits; ++i) {
    KLOG(level, " %x", desc->PortBits[num_port_bits - i - 1]);
  }
  KLOG(level, "\n");
}

// Per-device data for the hub driver.
typedef struct {
  // Index of the status change endpoint.
  int status_change_idx;

  // Hub descriptor.
  usb_hubd_desc_t hub_desc;

  // Status change data (length assuming the maximum 255 ports).
  uint8_t status_change_buf[9];

  // Reusable status change IRP.
  usb_irp_t status_change_irp;

  // Port status/status change for each port in the hub (2 uint16_ts per port).
  uint16_t* port_status;

  // The port we're currently handling changes to, or -1 if we aren't handling
  // any port's changes.
  int current_port;

  // List of events that need to be handled before we look for more status
  // changes.
  list_t pending_port_events;
} usb_hubd_data_t;

// Get the hub change bit from the status_change_buf.
static inline int get_hub_change_bit(const uint8_t status_change_buf[9]) {
  return status_change_buf[0] & 0x01;
}

// Get the port change bit from the status change buf.
static inline int get_port_change_bit(const uint8_t status_change_buf[9],
                                      int port) {
  KASSERT(port > 0 && port < 256);
  const int bit = port;  // ports are 1-indexed.
  const int byte = bit / 8;
  const uint8_t mask = 1 << (bit % 8);
  return status_change_buf[byte] & mask;
}

// Clear the port change bit.
static inline void clear_port_change_bit(uint8_t status_change_buf[9],
                                         int port) {
  KASSERT(port > 0 && port < 256);
  const int bit = port;  // ports are 1-indexed.
  const int byte = bit / 8;
  const uint8_t mask = 1 << (bit % 8);
  status_change_buf[byte] &= ~mask;
}

static uint16_t hubd_get_port_status(const usb_hubd_data_t* hubd, int port) {
  return hubd->port_status[2 * (port - 1)];
}

static uint16_t hubd_get_port_change(const usb_hubd_data_t* hubd, int port) {
  return hubd->port_status[2 * (port - 1) + 1];
}

// An event on a port that needs to be handled.
typedef struct {
  enum {
    PORT_NONE,
    PORT_CONNECTED,
    PORT_DISCONNECTED,
    PORT_ERROR,
    PORT_RESET_DONE,
  } type;

  usb_device_t* dev;  // The hub.
  int port;
  list_link_t link;
} port_event_t;

static const char* port_event_type_str(const port_event_t* event) {
  switch (event->type) {
    case PORT_NONE: return "NONE";
    case PORT_CONNECTED: return "CONNECTED";
    case PORT_DISCONNECTED: return "DISCONNECTED";
    case PORT_ERROR: return "ERROR";
    case PORT_RESET_DONE: return "RESET_DONE";
  }
  return "<unknown>";
}

static void set_configuration_done(usb_device_t* dev, void* arg);
static void get_hub_desc(usb_device_t* dev);
static void get_hub_desc_done(usb_device_t* dev, int result);

static void start_status_change_irp(usb_device_t* dev);
static void status_change_irp_done(usb_device_t* dev, int result);

// Process all outstanding changes by getting hub/port statuses and taking the
// appropriate action.  If there are no pending changes, restart the status
// change IRP.
static void process_all_changes(usb_device_t* dev);

static void get_port_status(usb_device_t* dev, int port);
static void get_port_status_done(usb_device_t* dev, int result);

// Examines the port status and enqueues an event for it in pending_port_events.
static void handle_port_changes(usb_device_t* dev, int port);
static void ack_port_change_done(usb_device_t* dev, int result);

// Handles all the queued events for the device, then restarts the status change
// IRP.
static void handle_queued_events(usb_device_t* dev);
static void handle_one_event(usb_device_t* dev, port_event_t* event);
static void handle_one_event_done(usb_device_t* dev);

// Handle a connected port by creating a device, initializing it, etc.  Called
// by the USBD when the bus's default address is available.
static void connect_port(usb_bus_t* bus, void* arg);
static void connect_port_reset_sent(usb_device_t* dev, int result);
static void connect_port_reset_done(usb_device_t* dev);

static void set_configuration_done(usb_device_t* dev, void* arg) {
  KASSERT_DBG(dev->state == USB_DEV_CONFIGURED);
  KLOG(DEBUG, "USB HUBD: hub %d.%d configuration done\n", dev->bus->bus_index,
       dev->address);

  // Sanity check the hub.
  int status_endpoint_idx = 0;
  for (int i = 1; i < USB_NUM_ENDPOINTS; ++i) {
    if (dev->endpoints[i]) {
      if (status_endpoint_idx > 0) {
        KLOG(WARNING, "USB HUBD: hub %d.%d has more than 1 endpoint; invalid\n",
             dev->bus->bus_index, dev->address);
        return;
      }
      status_endpoint_idx = i;
    }
  }
  ((usb_hubd_data_t*)dev->driver_data)->status_change_idx = status_endpoint_idx;

  if (status_endpoint_idx <= 0) {
    KLOG(WARNING, "USB HUBD: hub %d.%d has no status change endpoint; "
         "invalid\n", dev->bus->bus_index, dev->address);
    return;
  }

  usb_endpoint_t* status_change = dev->endpoints[status_endpoint_idx];
  if (status_change->type != USB_INTERRUPT ||
      status_change->dir != USB_IN) {
    KLOG(WARNING, "USB HUBD: hub %d.%d has an invalid status change endpoint "
         "(must be an IN/INTERRUPT endpoint)\n", dev->bus->bus_index,
         dev->address);
    return;
  }

  get_hub_desc(dev);
}

static void get_hub_desc(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  usb_hubd_get_hub_descriptor(dev, &hubd->hub_desc, &get_hub_desc_done);
}

static void get_hub_desc_done(usb_device_t* dev, int result) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KLOG(DEBUG, "USB HUBD: GET_DESCRIPTOR (hub) for hub %d.%d finished\n",
       dev->bus->bus_index, dev->address);

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
    KLOG(INFO, "USB HUBD: GET_HUB_DESCRIPTOR for %d.%d failed: %s\n",
         dev->bus->bus_index, dev->address, errorname(-result));
    // Don't continue with the initialization process; the hub is in an unknown
    // state.
    return;
  } else {
    KLOG(DEBUG2, "USB HUBD: hub descriptor for hub %d.%d:\n",
         dev->bus->bus_index, dev->address);
    usb_print_desc_hub(DEBUG2, &hubd->hub_desc);
  }

  hubd->port_status = (uint16_t*)kmalloc(
      2 * sizeof(uint16_t) * hubd->hub_desc.bNbrPorts);

  start_status_change_irp(dev);
}

static void start_status_change_irp(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  usb_hubd_get_status_change(dev, hubd->status_change_buf,
                             hubd->hub_desc.bNbrPorts,
                             hubd->status_change_idx,
                             status_change_irp_done);
}

static void status_change_irp_done(usb_device_t* dev, int result) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
    KLOG(INFO, "USB HUBD: reading STATUS CHANGE for %d.%d failed: %s\n",
         dev->bus->bus_index, dev->address, errorname(-result));
    // Don't continue with the initialization process; the hub is in an unknown
    // state.
    return;
  } else {
    KLOG(DEBUG2, "USB HUBD: status change for hub %d.%d: [",
         dev->bus->bus_index, dev->address);
    if (get_hub_change_bit(hubd->status_change_buf)) {
      KLOG(DEBUG2, " HUB");
    }
    for (int port = 1; port <= hubd->hub_desc.bNbrPorts; port++) {
      if (get_port_change_bit(hubd->status_change_buf, port)) {
        KLOG(DEBUG2, " P%d", port);
      }
    }
    KLOG(DEBUG2, " ]\n");
  }

  process_all_changes(dev);
}

static void process_all_changes(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;

  if (get_hub_change_bit(hubd->status_change_buf)) {
    // TODO(aoates): handle hub-level changes
    die("USB HUBD: hub-level changes unimplemented");
  }

  // Look for changed ports.  If we find a changed port, clear its change bit
  // and get its status.
  for (int port = 1; port <= hubd->hub_desc.bNbrPorts; port++) {
    if (get_port_change_bit(hubd->status_change_buf, port)) {
      KASSERT(hubd->current_port == -1);
      hubd->current_port = port;

      clear_port_change_bit(hubd->status_change_buf, port);
      get_port_status(dev, port);
      return;
    }
  }

  // If there are no remaining changes, handle the queued events.
  handle_queued_events(dev);
}

static void get_port_status(usb_device_t* dev, int port) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(port > 0 && port <= hubd->hub_desc.bNbrPorts);

  usb_hubd_get_port_status(dev, port, hubd->port_status + (2 * (port - 1)),
                           get_port_status_done);
}

static void get_port_status_done(usb_device_t* dev, int result) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  const int port = hubd->current_port;
  KASSERT(port > 0 && port <= hubd->hub_desc.bNbrPorts);

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
    KLOG(INFO, "USB HUBD: GET_PORT_STATUS for %d.%d/port %d failed: %s\n",
         dev->bus->bus_index, dev->address, port, errorname(-result));
    // Don't continue; the hub is in an unknown state.
    return;
  } else {
    const uint16_t port_status = hubd_get_port_status(hubd, port);
    const uint16_t port_change = hubd_get_port_change(hubd, port);
    KLOG(DEBUG2, "USB HUBD: GET_PORT_STATUS for hub %d.%d/port %d finished:\n",
         dev->bus->bus_index, dev->address, port);
    char buf[1024];
    flag_sprintf(buf, port_status, PORT_STATUS_FLAGS);
    KLOG(DEBUG2, "  PORT_STATUS: %s\n", buf);
    flag_sprintf(buf, port_change, PORT_CHANGE_FLAGS);
    KLOG(DEBUG2, "  PORT_CHANGE: %s\n", buf);
  }

  handle_port_changes(dev, port);
}

static void handle_port_changes(usb_device_t* dev, int port) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(port == hubd->current_port);

  const uint16_t port_status = hubd_get_port_status(hubd, port);
  const uint16_t port_change = hubd_get_port_change(hubd, port);

  port_event_t event;
  event.dev = dev;
  event.link = LIST_LINK_INIT;
  event.type = PORT_NONE;
  event.port = port;

  int feature_to_clear = -1;
  if (port_change & USB_HUBD_C_PORT_CONNECTION) {
    if (port_status & USB_HUBD_PORT_CONNECTION) {
      event.type = PORT_CONNECTED;
    } else {
      event.type = PORT_DISCONNECTED;
    }
    feature_to_clear = USB_HUBD_FEAT_C_PORT_CONNECTION;
  } else if (port_change & USB_HUBD_C_PORT_ENABLE) {
    // C_PORT_ENABLE should only be set when enable is 1 -> 0.
    KASSERT((port_status & USB_HUBD_PORT_ENABLE) == 0);
    event.type = ERROR;
    feature_to_clear = USB_HUBD_FEAT_C_PORT_ENABLE;
  } else if (port_change & USB_HUBD_C_PORT_SUSPEND) {
    // We shouldn't receive SUSPEND changes since we don't do suspends.
    die("USB HUBD: cannot handle SUSPEND change");
    feature_to_clear = USB_HUBD_FEAT_C_PORT_SUSPEND;
  } else if (port_change & USB_HUBD_C_PORT_OVER_CURRENT) {
    die("USB HUBD: cannot handle over-current condition");
    feature_to_clear = USB_HUBD_FEAT_C_PORT_OVER_CURRENT;
  } else if (port_change & USB_HUBD_C_PORT_RESET) {
    // C_PORT_RESET should only be set when enable is 0 -> 1.
    KASSERT(port_status & USB_HUBD_PORT_ENABLE);
    KASSERT((port_status & USB_HUBD_PORT_RESET) == 0);
    event.type = PORT_RESET_DONE;
    feature_to_clear = USB_HUBD_FEAT_C_PORT_RESET;
  }

  if (event.type != PORT_NONE) {
    KASSERT_DBG(feature_to_clear > 0);
    port_event_t* event_heap = (port_event_t*)kmalloc(sizeof(port_event_t));
    *event_heap = event;
    list_push(&hubd->pending_port_events, &event_heap->link);
  }

  if (feature_to_clear > 0) {
    usb_hubd_clear_port_feature(dev, port, feature_to_clear,
                                &ack_port_change_done);
    return;
  }

  // No more changes on this port; keep going.
  hubd->current_port = -1;
  process_all_changes(dev);
}

static void ack_port_change_done(usb_device_t* dev, int result) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  const int port = hubd->current_port;
  KASSERT(port > 0 && port <= hubd->hub_desc.bNbrPorts);

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
    KLOG(INFO, "USB HUBD: CLEAR_PORT_FEATURE for %d.%d/port %d failed: %s\n",
         dev->bus->bus_index, dev->address, port, errorname(-result));
    // Don't continue; the hub is in an unknown state.
    return;
  } else {
    // TODO(aoates): instead of re-getting the port status each time, should we
    // just process the bits as we see them the once?
    get_port_status(dev, port);
  }
}

static void handle_queued_events(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(hubd->current_port == -1);

  // All the change bits should have been cleared by now.
  if (ENABLE_KERNEL_SAFETY_NETS) {
    KASSERT_DBG(get_hub_change_bit(hubd->status_change_buf) == 0);
    for (int port = 1; port <= hubd->hub_desc.bNbrPorts; port++)
      KASSERT_DBG(get_port_change_bit(hubd->status_change_buf, port) == 0);
  }

  // Find an event to handle.
  list_link_t* link = list_pop(&hubd->pending_port_events);
  if (link) {
    port_event_t* event = container_of(link, port_event_t, link);
    handle_one_event(dev, event);
    return;
  }

  // If no events are left, start the status change IRP again.
  start_status_change_irp(dev);
}

static void handle_one_event(usb_device_t* dev, port_event_t* event) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(hubd->current_port == -1);

  KLOG(DEBUG2, "USB HUBD: handling hub %d.%d event: port %d %s\n",
       dev->bus->bus_index, dev->address, event->port,
       port_event_type_str(event));

  hubd->current_port = event->port;

  switch (event->type) {
    case PORT_NONE:
      die("NONE event should never be generated");

    case PORT_CONNECTED:
      usb_acquire_default_address(dev->bus, &connect_port, event);
      handle_one_event_done(dev);
      return;

    case PORT_RESET_DONE:
      kfree(event);
      connect_port_reset_done(dev);
      return;

    case PORT_DISCONNECTED:
    case PORT_ERROR:
      // TODO(aoates): implement
      die("unimplemented USB event");
  }

  die("unreachable");
}

static void handle_one_event_done(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(hubd->current_port > 0);

  hubd->current_port = -1;
  handle_queued_events(dev);
}

// We may have multiple of these pending for different ports, waiting for the
// default address to be free, so we have to track the device and port
// associated with each call.
//
// We can't block the event pipeline until a particular port is connected
// because we need to process RESET_DONE events.
static void connect_port(usb_bus_t* bus, void* arg) {
  port_event_t* event = (port_event_t*)arg;

  // We now have the default address.  We reset the port.  Once it's enabled,
  // we'll create a device, assign an address, put it in the device tree, etc.
  usb_hubd_set_port_feature(event->dev, event->port, USB_HUBD_FEAT_PORT_RESET,
                            &connect_port_reset_sent);
}

static void connect_port_reset_sent(usb_device_t* dev, int result) {
  if (result) {
    KLOG(WARNING, "USB HUBD: unable to reset connected port: %s\n",
         errorname(-result));
    // TODO(aoates): what else should we do?
  }

  // The reset request is done, but the reset itself may not be.  We'll catch
  // that in a future status change.

  // Just drop the current thread of control --- we should have started
  // processing events again when we acquired the default address before
  // starting the reset.
}

static void connect_port_reset_done(usb_device_t* dev) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(hubd->current_port > 0);
  const int port = hubd->current_port;

  const uint16_t port_status = hubd_get_port_status(hubd, port);

  // Check if the reset succeeded.
  if (!(port_status & USB_HUBD_PORT_ENABLE)) {
    KLOG(WARNING, "USB HUBD: unable to reset hub %d.%d port %d\n",
         dev->bus->bus_index, dev->address, port);
    usb_release_default_address(dev->bus);
    // TODO(aoates): what else should we do?
  } else {
    // Reset succeeded and the port is enabled!  Create a device, insert it into
    // the device tree, and initialize it.
    const usb_speed_t child_speed = (port_status & USB_HUBD_PORT_LOW_SPEED)
        ? USB_LOW_SPEED : USB_FULL_SPEED;
    usb_device_t* child = usb_create_device(dev->bus, dev, child_speed);
    child->state = USB_DEV_DEFAULT;
    usb_init_device(child);
  }

  handle_one_event_done(dev);
}

int usb_hubd_check_device(usb_device_t* dev) {
  KASSERT_DBG(dev->state == USB_DEV_ADDRESS);
  KASSERT_DBG(dev->dev_desc.bDescriptorType = USB_DESC_DEVICE);

  if (dev->dev_desc.bDeviceClass == USB_HUBD_HUB_CLASSCODE &&
      dev->dev_desc.bDeviceSubClass == 0 &&
      dev->dev_desc.bDeviceProtocol == 0) {
    if (dev->dev_desc.bLength != 0x12 ||
        dev->dev_desc.bNumConfigurations != 1 ||
        dev->speed != USB_FULL_SPEED) {
      // Note: it seems that the USB spec requires bMaxPacketSize0 to be 64, but
      // for QEMU virtual hubs it's 8, so we don't bother checking it.
      KLOG(WARNING, "invalid USB hub device descriptor; ignoring\n");
      return 0;
    }

    return 1;
  }

  return 0;
}

int usb_hubd_adopt_device(usb_device_t* dev) {
  KLOG(DEBUG, "USB HUBD: found device\n");

  usb_hubd_data_t* data =
      (usb_hubd_data_t*)kmalloc(sizeof(usb_hubd_data_t));
  kmemset(data, 0, sizeof(usb_hubd_data_t));
  data->current_port = -1;
  data->pending_port_events = LIST_INIT;
  dev->driver_data = data;

  // Step 1: configure the hub.
  KASSERT_DBG(dev->dev_desc.bNumConfigurations == 1);
  uint8_t config;
  usb_get_configuration_values(dev, &config);
  KLOG(DEBUG, "USB HUBD: configuring hub %d.%d (config %d)\n", dev->bus->bus_index,
       dev->address, config);
  usb_set_configuration(dev, config, &set_configuration_done, dev);

  return 0;
}
