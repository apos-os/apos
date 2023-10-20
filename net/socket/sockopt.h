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

// Helpers for dealing with socket options.
#ifndef APOO_NET_SOCKET_SOCKOPT_H
#define APOO_NET_SOCKET_SOCKOPT_H

#include "dev/timer.h"
#include "user/include/apos/net/socket/socket.h"

// Implements net_getsockopt() for an int-valued sockopt.  Supplies the given
// int as the option value, or returns -error.
int getsockopt_int(void* val, socklen_t* val_len, int option_value);

// Implements net_setsockopt() for an int-valued sockopt.  Sets *option_value to
// the parsed value, or returns -error.
int setsockopt_int(const void* val, socklen_t val_len, int* option_value);

// As above, but for struct timeval sockopts.  Converts to/from a ms value, and
// converts zero (disabled timeout) to -1 (what scheduler_wait* take for a
// disabled timeout).
int getsockopt_tvms(void* val, socklen_t* val_len, long option_value);
int setsockopt_tvms(const void* val, socklen_t val_len,
                    long* option_value);

#endif
