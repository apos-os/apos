// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_ETH_MAC_H
#define APOO_NET_ETH_MAC_H

#include <stdint.h>

#include "net/mac.h"

#define ETH_MAC_LEN 6
_Static_assert(NIC_MAC_LEN >= ETH_MAC_LEN,
               "Cannot store an ETH MAC in a NIC MAC");

// Copy the broadcast address into the given buffer.
void eth_mkbroadcast(uint8_t* mac);

#endif
