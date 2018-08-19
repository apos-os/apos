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

#include "memory/block_cache.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static void create_test(void) {
  KTEST_BEGIN("net_socket_create(UDP): basic creation");
  socket_t* sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_INET, SOCK_DGRAM, 0, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_INET, sock->s_domain);
  KEXPECT_EQ(SOCK_DGRAM, sock->s_type);
  KEXPECT_EQ(IPPROTO_UDP, sock->s_protocol);
  net_socket_destroy(sock);

  KTEST_BEGIN("net_socket(UDP): basic creation");
  int fd = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(fd, 0);

  KTEST_BEGIN("net_socket(UDP): fstat() on open AF_UNIX socket");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(0, VFS_S_ISSOCK(stat.st_size));
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("net_socket(AF_UNIX): bad type");
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_INET, -1, 0));
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_INET, 5, 0));

  KTEST_BEGIN("net_socket(AF_UNIX): bad protocol");
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_DGRAM, -1));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_DGRAM, 1));
}

static void unsupported_ops_test(void) {
  KTEST_BEGIN("UDP sockets: listen() unsupported");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-EOPNOTSUPP, net_listen(sock, 10));

  KTEST_BEGIN("UDP sockets: accept() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_accept(sock, NULL, NULL));

  KTEST_BEGIN("UDP sockets: accept_queue_length() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_accept_queue_length(sock));

  KEXPECT_EQ(0, vfs_close(sock));
}

void socket_udp_test(void) {
  KTEST_SUITE_BEGIN("Socket (UDP)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  unsupported_ops_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
