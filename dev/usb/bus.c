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

#include "common/kassert.h"
#include "common/kstring.h"
#include "common/klog.h"
#include "dev/usb/bus.h"
#include "dev/usb/hcd.h"
#include "dev/usb/usb.h"

// The maximum number of buses we will support.
#define MAX_BUSES 10
static usb_bus_t g_buses[MAX_BUSES];
static int g_num_buses = 0;

void usb_create_bus(usb_hcdi_t* hc) {
  KASSERT(usb_is_initialized() == 0);
  if (g_num_buses >= MAX_BUSES) {
    klogfm(KL_USB, WARNING, "USB: too many USB host controllers!\n");
    return;
  }

  // Pre-initialize the next bus.  The rest of the initialization will happen
  // when the USB subsystem is fully initialized.
  int bus_idx = g_num_buses++;
  usb_bus_t* bus = &g_buses[bus_idx];
  kmemset(bus, 0, sizeof(usb_bus_t));
  bus->bus_index = bus_idx;
  bus->hcd = hc;
  bus->queued_address_callbacks = LIST_INIT;
}

int usb_num_buses(void) {
  return g_num_buses;
}

usb_bus_t* usb_get_bus(int i) {
  if (i < 0 || i >= g_num_buses) {
    return 0x0;
  }
  return &g_buses[i];
}
