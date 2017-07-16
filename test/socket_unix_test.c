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

#include "memory/kmalloc.h"
#include "net/socket/socket.h"
#include "test/ktest.h"
#include "user/include/apos/errors.h"
#include "vfs/vfs.h"

static void create_test(void) {
  KTEST_BEGIN("net_socket_create(AF_UNIX): basic creation");
  socket_t* sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_UNIX, SOCK_STREAM, 0, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_UNIX, sock->s_domain);
  KEXPECT_EQ(SOCK_STREAM, sock->s_type);
  KEXPECT_EQ(0, sock->s_protocol);
  kfree(sock);

  KTEST_BEGIN("net_socket_create(AF_UNIX): bad type");
  sock = NULL;
  KEXPECT_EQ(-EPROTOTYPE, net_socket_create(AF_UNIX, -1, 0, &sock));
  KEXPECT_EQ(NULL, sock);
  KEXPECT_EQ(-EPROTOTYPE, net_socket_create(AF_UNIX, 5, 0, &sock));
  KEXPECT_EQ(NULL, sock);
  // TODO(aoates): test SOCK_DGRAM, etc when they're defined.

  KTEST_BEGIN("net_socket_create(AF_UNIX): bad protocol");
  KEXPECT_EQ(-EPROTONOSUPPORT,
             net_socket_create(AF_UNIX, SOCK_STREAM, -1, &sock));
  KEXPECT_EQ(NULL, sock);
  KEXPECT_EQ(-EPROTONOSUPPORT,
             net_socket_create(AF_UNIX, SOCK_STREAM, 1, &sock));
  KEXPECT_EQ(NULL, sock);

  KTEST_BEGIN("net_socket(AF_UNIX): basic creation");
  int fd = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(fd, 0);

  KTEST_BEGIN("net_socket(AF_UNIX): fstat() on open AF_UNIX socket");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(0, VFS_S_ISSOCK(stat.st_size));
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("net_socket(AF_UNIX): bad type");
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_UNIX, -1, 0));
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_UNIX, 5, 0));
  // TODO(aoates): test SOCK_DGRAM, etc when they're defined.

  KTEST_BEGIN("net_socket(AF_UNIX): bad protocol");
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_UNIX, SOCK_STREAM, -1));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_UNIX, SOCK_STREAM, 1));

  // TODO(aoates): test failures in net_socket().
}

void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Socket (Unix Domain)");
  create_test();
}
