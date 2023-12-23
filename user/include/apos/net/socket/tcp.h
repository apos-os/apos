// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_USER_INCLUDE_APOS_NET_SOCKET_TCP_H
#define APOO_USER_INCLUDE_APOS_NET_SOCKET_TCP_H

// Non-standard socket options.

// Gets/sets the initial sequence number on the socket.
#define SO_TCP_SEQ_NUM 1

// Gets the current socket state.
#define SO_TCP_SOCKSTATE 2

// Sets the time spent in TIME_WAIT.
#define SO_TCP_TIME_WAIT_LEN 3

// Sets the current and minimun RTO values, in milliseconds.
#define SO_TCP_RTO 4
#define SO_TCP_RTO_MIN 5

#endif
