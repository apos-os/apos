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

#include "test/kernel_tests.h"

#include "net/socket/socket.h"
#include "test/ktest.h"
#include "user/include/apos/errors.h"

void socket_test(void) {
  KTEST_SUITE_BEGIN("Socket");

  KTEST_BEGIN("net_socket_create() with invalid domain");
  socket_t* sock = NULL;
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket_create(-1, SOCK_STREAM, 0, &sock));
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket_create(5, SOCK_STREAM, 0, &sock));
  KEXPECT_EQ(NULL, sock);

  KTEST_BEGIN("net_socket() with invalid domain");
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket(-1, SOCK_STREAM, 0));
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket(5, SOCK_STREAM, 0));
}
