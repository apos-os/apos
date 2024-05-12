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

#ifndef APOO_NET_IP_IP6_H
#define APOO_NET_IP_IP6_H

#include "dev/net/nic.h"

// Enable IPv6 on the given NIC.  Configures a link-local address and kicks off
// the configuration process.  No-op if the NIC already has an IPv6 address.
void ipv6_enable(nic_t* nic);

void ip6_recv(nic_t* nic, pbuf_t* pb);

#endif
