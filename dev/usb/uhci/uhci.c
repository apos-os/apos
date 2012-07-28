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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/pci/pci.h"
#include "dev/pci/pci-driver.h"
#include "dev/usb/uhci/uhci.h"

#define UHCI_MAX_CONTROLLERS 10
static usb_uhci_t g_controllers[UHCI_MAX_CONTROLLERS];
static int g_num_controllers = 0;

void usb_uhci_register_controller(usb_uhci_t c) {
  if (g_num_controllers >= UHCI_MAX_CONTROLLERS) {
    klogf("WARNING: too many UHCI controllers; ignoring\n");
    return;
  }
  g_controllers[g_num_controllers++] = c;
  klogf("USB: found UHCI controller #%d (at 0x%x)\n", g_num_controllers,
        c.base_port);
}

int usb_uhci_num_controllers() {
  return g_num_controllers;
}

usb_uhci_t* usb_uhci_get_controller(int i) {
  if (i < 0 || i >= g_num_controllers) {
    return 0x0;
  }
  return &g_controllers[i];
}
