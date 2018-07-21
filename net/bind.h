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

#ifndef APOO_NET_BIND_H
#define APOO_NET_BIND_H

#include "net/addr.h"
#include "user/include/apos/net/socket/inet.h"

// Returns 0 if the given address is bindable, or -error.
int inet_bindable(const netaddr_t* addr);

// Chooses a default bind address for the given address family.  Returns the
// address of the chosen NIC if successful, or -error if an address isn't found.
int inet_choose_bind(addrfam_t family, netaddr_t* addr_out);

#endif
