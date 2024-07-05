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

#ifndef APOO_NET_IP_IP6_INTERNAL_H
#define APOO_NET_IP_IP6_INTERNAL_H

#include "dev/net/nic.h"
#include "net/ip/icmpv6/ndp_protocol.h"
#include "net/ip/ip6_hdr.h"

// Indicate that we got a neighbor advertisement for given IP address ---
// handles duplicate address detection logic.
void ip6_nic_got_nbr_advert(nic_t* nic, const ip6_hdr_t* ip6_hdr,
                            const ndp_nbr_advert_t* advert);

#endif
