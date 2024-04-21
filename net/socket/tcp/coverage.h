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

#ifndef APOO_NET_SOCKET_TCP_COVERAGE_H
#define APOO_NET_SOCKET_TCP_COVERAGE_H

#include "net/socket/tcp/socket.h"

// If true, coverage data is tracked.
#define TCP_ENABLE_COVERAGE 0

#if TCP_ENABLE_COVERAGE
#define tcp_coverage_log(event, socket) tcp_coverage_log_do(event, socket)
#else
#define tcp_coverage_log(event, socket)
#endif

// Record an event for coverage tracking.
void tcp_coverage_log_do(const char* event, const socket_tcp_t* socket);

// Dump coverage data.
void tcp_coverage_dump(void);


#endif
