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
#include "common/math.h"
#include "dev/usb/drivers/hub/control.h"
#include "dev/usb/drivers/hub/request.h"
#include "dev/usb/usb_driver.h"
#include "memory/kmalloc.h"
#include "util/flag_printf.h"

flag_spec_t PORT_STATUS_FLAGS[] = {
  FLAG_SPEC_FLAG("PORT_CONNECTION", 0x0001),
  FLAG_SPEC_FLAG("PORT_ENABLE", 0x0002),
  FLAG_SPEC_FLAG("PORT_SUSPEND", 0x0004),
  FLAG_SPEC_FLAG("PORT_OVER_CURRENT", 0x0008),
  FLAG_SPEC_FLAG("PORT_RESET", 0x0010),
  FLAG_SPEC_FLAG("PORT_POWER", 0x0100),
  FLAG_SPEC_FLAG("PORT_LOW_SPEED", 0x0200),
  FLAG_SPEC_FLAG("PORT_HIGH_SPEED", 0x0400),
  FLAG_SPEC_FLAG("PORT_TEST", 0x0800),
  FLAG_SPEC_FLAG("PORT_INDICATOR", 0x1000),
  FLAG_SPEC_END,
};

flag_spec_t PORT_CHANGE_FLAGS[] = {
  FLAG_SPEC_FLAG("C_PORT_CONNECTION", 0x0001),
  FLAG_SPEC_FLAG("C_PORT_ENABLE", 0x0002),
  FLAG_SPEC_FLAG("C_PORT_SUSPEND", 0x0004),
  FLAG_SPEC_FLAG("C_PORT_OVER_CURRENT", 0x0008),
  FLAG_SPEC_FLAG("C_PORT_RESET", 0x0010),
  FLAG_SPEC_END,
};

static void usb_print_desc_hub(usb_hubd_desc_t* desc) {
  KASSERT_DBG(desc->bDescriptorType == USB_HUBD_DESC_TYPE);
  klogf("  bDescLength: %d\n", desc->bLength);
  klogf("  bDescriptorType: HUB (%d)\n", desc->bDescriptorType);
  klogf("  bNbrPorts: %d\n", desc->bNbrPorts);
  klogf("  wHubCharacteristics: 0x%x\n", desc->wHubCharacteristics);
  klogf("  bPwrOn2PwrGood: %d\n", desc->bPwrOn2PwrGood);
  klogf("  bHubContrCurrent: %d\n", desc->bHubContrCurrent);

  klogf("  PortBits:");
  const int num_port_bits = 2 * ceiling_div(desc->bNbrPorts, 8);
  for (int i = 0; i < num_port_bits; ++i) {
    klogf(" %x", desc->PortBits[num_port_bits - i - 1]);
  }
  klogf("\n");
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

  // The port we're currently querying the status of, or -1 if we aren't
  // querying any port's status.
  int current_port_status;
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

static void set_configuration_done(usb_device_t* dev, void* arg) {
  KASSERT_DBG(dev->state == USB_DEV_CONFIGURED);
  klogf("USB HUBD: hub %d.%d configuration done\n", dev->bus->bus_index,
        dev->address);

  // Sanity check the hub.
  int status_endpoint_idx = 0;
  for (int i = 1; i < USB_NUM_ENDPOINTS; ++i) {
    if (dev->endpoints[i]) {
      if (status_endpoint_idx > 0) {
        klogf("USB HUBD: hub %d.%d has more than 1 endpoint; invalid\n",
              dev->bus->bus_index, dev->address);
        return;
      }
      status_endpoint_idx = i;
    }
  }
  ((usb_hubd_data_t*)dev->driver_data)->status_change_idx = status_endpoint_idx;

  if (status_endpoint_idx <= 0) {
    klogf("USB HUBD: hub %d.%d has no status change endpoint; invalid\n",
          dev->bus->bus_index, dev->address);
    return;
  }

  usb_endpoint_t* status_change = dev->endpoints[status_endpoint_idx];
  if (status_change->type != USB_INTERRUPT ||
      status_change->dir != USB_IN) {
    klogf("USB HUBD: hub %d.%d has an invalid status change endpoint "
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
  klogf("USB HUBD: GET_DESCRIPTOR (hub) for hub %d.%d finished\n",
        dev->bus->bus_index, dev->address);

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
  } else {
    klogf("USB HUBD: hub descriptor for hub %d.%d:\n",
          dev->bus->bus_index, dev->address);
    usb_print_desc_hub(&hubd->hub_desc);
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
  } else {
    klogf("USB HUBD: status change for hub %d.%d: [",
        dev->bus->bus_index, dev->address);
    if (get_hub_change_bit(hubd->status_change_buf)) {
      klogf(" HUB");
    }
    for (int port = 1; port <= hubd->hub_desc.bNbrPorts; port++) {
      if (get_port_change_bit(hubd->status_change_buf, port)) {
        klogf(" P%d", port);
      }
    }
    klogf(" ]\n");
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
      clear_port_change_bit(hubd->status_change_buf, port);
      get_port_status(dev, port);
      return;
    }
  }

  // If no changes were found, start the status change IRP again.
  start_status_change_irp(dev);
}

static void get_port_status(usb_device_t* dev, int port) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  KASSERT(port > 0 && port <= hubd->hub_desc.bNbrPorts);
  KASSERT(hubd->current_port_status == -1);

  hubd->current_port_status = port;

  usb_hubd_get_port_status(dev, port, hubd->port_status + (2 * (port - 1)),
                           get_port_status_done);
}

static void get_port_status_done(usb_device_t* dev, int result) {
  usb_hubd_data_t* hubd = (usb_hubd_data_t*)dev->driver_data;
  const int port = hubd->current_port_status;
  KASSERT(port > 0 && port <= hubd->hub_desc.bNbrPorts);

  if (result) {
    // TODO(aoates): mark hub as invalid somehow.
  } else {
    const uint16_t port_status = hubd->port_status[2 * (port - 1)];
    const uint16_t port_change = hubd->port_status[2 * (port - 1) + 1];
    klogf("USB HUBD: GET_PORT_STATUS for hub %d.%d/port %d finished:\n",
          dev->bus->bus_index, dev->address, port);
    char buf[1024];
    flag_sprintf(buf, port_status, PORT_STATUS_FLAGS);
    klogf("  PORT_STATUS: %s\n", buf);
    flag_sprintf(buf, port_change, PORT_CHANGE_FLAGS);
    klogf("  PORT_CHANGE: %s\n", buf);
  }

  hubd->current_port_status = -1;
  process_all_changes(dev);
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
      klogf("Warning: invalid USB hub device descriptor; ignoring\n");
      return 0;
    }

    return 1;
  }

  return 0;
}

int usb_hubd_adopt_device(usb_device_t* dev) {
  klogf("USB HUBD: found device\n");

  usb_hubd_data_t* data =
      (usb_hubd_data_t*)kmalloc(sizeof(usb_hubd_data_t));
  kmemset(data, 0, sizeof(usb_hubd_data_t));
  data->current_port_status = -1;
  dev->driver_data = data;

  // Step 1: configure the hub.
  KASSERT_DBG(dev->dev_desc.bNumConfigurations == 1);
  uint8_t config;
  usb_get_configuration_values(dev, &config);
  klogf("USB HUBD: configuring hub %d.%d (config %d)\n", dev->bus->bus_index,
        dev->address, config);
  usb_set_configuration(dev, config, &set_configuration_done, dev);

  return 0;
}
