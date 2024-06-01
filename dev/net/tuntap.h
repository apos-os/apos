// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

// Driver for a basic TUN/TAP device.
#ifndef APOO_DEV_NET_TUNTAP_H
#define APOO_DEV_NET_TUNTAP_H

#include "dev/dev.h"
#include "dev/net/nic.h"

// TUN/TAP flags.
#define TUNTAP_TAP_MODE 0x1  // Operate in L2 (tap) rather than L3 (tun) mode.
#define TUNTAP_TUN_IPV6 0x2  // Create an IPv6 (rather than IPv4) TUN device.

// Create and register a TUN/TAP device.  |bufsize| is the number of bytes
// (approximately) that will be buffered each on the rx and tx sides.
nic_t* tuntap_create(ssize_t bufsize, int flags, apos_dev_t* id);

// Destroy a TUN/TAP device.
int tuntap_destroy(apos_dev_t id);

#endif
