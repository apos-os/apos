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


#include "test/kernel_tests.h"

#include "common/errno.h"
#include "memory/kmalloc.h"
#include "net/socket/socket.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs_test_util.h"

static void create_test(void) {
  KTEST_BEGIN("net_socket_create(SOCK_RAW): basic creation");
  socket_t* sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_INET, SOCK_RAW, IPPROTO_ICMP, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_INET, sock->s_domain);
  KEXPECT_EQ(SOCK_RAW, sock->s_type);
  KEXPECT_EQ(IPPROTO_ICMP, sock->s_protocol);
  net_socket_destroy(sock);

  sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_INET, SOCK_RAW, 123, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_INET, sock->s_domain);
  KEXPECT_EQ(SOCK_RAW, sock->s_type);
  KEXPECT_EQ(123, sock->s_protocol);
  net_socket_destroy(sock);

  KTEST_BEGIN("net_socket_create(SOCK_RAW): unsupported domain");
  sock = NULL;
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket_create(AF_UNIX, SOCK_RAW, 10, &sock));
  KEXPECT_EQ(NULL, sock);
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket_create(10, SOCK_RAW, 10, &sock));
  KEXPECT_EQ(NULL, sock);

  KTEST_BEGIN("net_socket_create(SOCK_RAW): unsupported protocol");
  sock = NULL;
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket_create(AF_INET, SOCK_RAW, 0, &sock));
  KEXPECT_EQ(NULL, sock);
}

static void unsupported_ops_test(void) {
  KTEST_BEGIN("Raw sockets: listen() unsupported");
  int sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-EOPNOTSUPP, net_listen(sock, 10));

  KTEST_BEGIN("Raw sockets: accept() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_accept(sock, NULL, NULL));

  KTEST_BEGIN("Raw sockets: connect() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_connect(sock, NULL, 0));

  KTEST_BEGIN("Raw sockets: accept_queue_length() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_accept_queue_length(sock));

  KEXPECT_EQ(0, vfs_close(sock));
}

void socket_raw_test(void) {
  KTEST_SUITE_BEGIN("Socket (raw)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  unsupported_ops_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
