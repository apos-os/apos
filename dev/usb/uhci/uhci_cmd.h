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

// Commands for testing and manipulating UHCI controllers from the kshell.
#ifndef APOO_DEV_USB_UHCI_UHCI_CMD_H
#define APOO_DEV_USB_UHCI_UHCI_CMD_H

// Process a command line.  The first argument is assumed to be 'uhci'.
void uhci_cmd(int argc, char* argv[]);

#endif
