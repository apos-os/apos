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

#ifndef APOO_NET_ETH_ETHERTYPE_H
#define APOO_NET_ETH_ETHERTYPE_H

// Protocol types.  Used in the ethernet frame header, of course, but also
// throughout the network stack to identify protocols (even if they aren't bound
// for an ethernet device).
typedef enum {
  ET_IPV4 = 0x0800,
  ET_IPV6 = 0x86DD,
  ET_ARP = 0x0806,
} ethertype_t;

#endif
