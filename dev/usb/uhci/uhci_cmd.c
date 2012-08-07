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

#include "common/kstring.h"
#include "dev/usb/hcd.h"
#include "dev/usb/uhci/uhci-internal.h"
#include "dev/usb/uhci/uhci.h"
#include "dev/usb/usb.h"
#include "kshell.h"

// Test the UHCI controller(s).
void uhci_cmd(int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: uhci <idx> <port>\n");
    return;
  }
  int idx = atoi(argv[1]);
  int port = atoi(argv[2]);
  if (idx >= usb_num_host_controllers()) {
    ksh_printf("error: invalid controller %d\n", idx);
    return;
  }
  // Test the USB controller.
  uhci_test_controller(usb_get_host_controller(idx), port);
}
