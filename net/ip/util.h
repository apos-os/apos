// Copyright 2018 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_IP_UTIL_H
#define APOO_NET_IP_UTIL_H

#include "net/addr.h"
#include "dev/net/nic.h"
#include "user/include/apos/net/socket/inet.h"

// Given a destination address, pick a source address that can route to it (or
// return an error).
int ip_pick_src(const struct sockaddr* dst, socklen_t dst_len,
                struct sockaddr_storage* src_out);

int ip_pick_src_netaddr(const netaddr_t* dst, netaddr_t* src_out);

// As above, but restricted to a particular NIC.
int ip6_pick_nic_src(const netaddr_t* dst, nic_t* nic, netaddr_t* src_out);

// As above, but with the NIC locked.
int ip6_pick_nic_src_locked(const netaddr_t* dst, nic_t* nic,
                            netaddr_t* src_out);

#endif
