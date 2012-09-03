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
static int g_bus_initialized = 0;

void usb_create_bus(usb_hcdi_t* hc) {
  KASSERT(g_bus_initialized == 0);
  if (g_num_buses >= MAX_BUSES) {
    klogf("WARNING: too many USB host controllers!\n");
    return;
  }

  // Pre-initialize the next bus.  The rest of the initialization will happen
  // when the USB subsystem is fully initialized.
  usb_bus_t* bus = &g_buses[g_num_buses++];
  kmemset(bus, 0, sizeof(usb_bus_t));
  bus->hcd = hc;
}

int usb_num_buses() {
  return g_num_buses;
}

usb_bus_t* usb_get_bus(int i) {
  if (i < 0 || i >= g_num_buses) {
    return 0x0;
  }
  return &g_buses[i];
}
