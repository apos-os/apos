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

#ifndef APOO_NET_IP_ICMPV6_ICMPV6_H
#define APOO_NET_IP_ICMPV6_ICMPV6_H

#include "dev/net/nic.h"
#include "net/ip/ip6_hdr.h"
#include "net/pbuf.h"

// Dispatch a packet.  The IPv6 header may be part of the pbuf_t.  |offset| is
// how far into the pbuf_t the ICMPv6 packet starts.
bool icmpv6_recv(nic_t* nic, const ip6_hdr_t* ip_hdr, size_t offset,
                 pbuf_t* pb);

#endif
