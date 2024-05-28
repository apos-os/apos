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

#ifndef APOO_NET_IP_IP6_ADDR_H
#define APOO_NET_IP_IP6_ADDR_H

#include "user/include/apos/net/socket/inet.h"

// Returns the number of bits shared between the two addresses.
int ip6_common_prefix(const struct in6_addr* A, const struct in6_addr* B);

#endif
