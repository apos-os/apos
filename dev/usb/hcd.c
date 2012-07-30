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

#include "common/klog.h"
#include "dev/usb/usb.h"
#include "dev/usb/hcd.h"

// The maximum number of host controllers we will support.
#define MAX_HCS 10
static usb_hcdi_t g_hcs[MAX_HCS];
static int g_num_hcs = 0;

void usb_register_host_controller(usb_hcdi_t hc) {
  if (g_num_hcs >= MAX_HCS) {
    klogf("WARNING: too many USB host controllers!\n");
    return;
  }
  g_hcs[g_num_hcs++] = hc;
}
