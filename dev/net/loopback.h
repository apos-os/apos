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

#ifndef APOO_DEV_NET_LOOPBACK_H
#define APOO_DEV_NET_LOOPBACK_H

#include "dev/net/nic.h"
#include "net/eth/ethertype.h"

// Queue a packet to send on the given loopback nic.  It will be dispatched in a
// defint ASAP.  Never blocks.
void loopback_send(nic_t* nic, pbuf_t* pb, ethertype_t protocol);

// Creates a and registers a loopback NIC, returning it for convenience.
nic_t* loopback_create(void);

#endif
