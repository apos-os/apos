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

// Definitions for POSIX's <sys/un.h>
#ifndef APOO_USER_NET_SOCKET_UNIX_H
#define APOO_USER_NET_SOCKET_UNIX_H

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/net/socket/socket.h"
#else
#  include <apos/net/socket/socket.h>
#endif

struct sockaddr_un {
  sa_family_t sun_family;  // Address family.
  char sun_path[108];      //  Socket pathname.
};

_Static_assert(sizeof(struct sockaddr_un) <= sizeof(struct sockaddr_storage),
               "struct sockaddr_un too large for struct sockaddr_storage");

#endif
