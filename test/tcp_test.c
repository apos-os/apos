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

#include "net/addr.h"
#include "net/bind.h"
#include "net/socket/socket.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static void tcp_socket_test(void) {
  KTEST_BEGIN("Basic TCP socket creation");
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("Basic TCP socket creation (default protocol)");
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("Basic TCP socket creation (bad protocol)");
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, 1000));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, -1));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, IPPROTO_UDP));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, IPPROTO_ICMP));
}

static void sockopt_test(void) {
  KTEST_BEGIN("TCP socket: getsockopt");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  int val[2];
  socklen_t vallen = sizeof(int) * 2;
  KEXPECT_EQ(0, net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(SOCK_STREAM, val[0]);

  KEXPECT_EQ(-ENOPROTOOPT,
             net_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val[0], &vallen));

  KTEST_BEGIN("TCP socket: setsockopt");
  KEXPECT_EQ(-ENOPROTOOPT,
             net_setsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], vallen));

  KEXPECT_EQ(0, vfs_close(sock));
}

static void bind_test(void) {
  KTEST_BEGIN("bind(SOCK_STREAM): can bind to NIC's address");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_port = 1234;

  KTEST_BEGIN("getsockname(SOCK_STREAM): unbound socket");
  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_UNSPEC, result_addr->sin_family);

  KTEST_BEGIN("getpeername(SOCK_STREAM): unbound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("getsockname(SOCK_STREAM): bound socket");
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(addr.sin_addr.s_addr, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(1234, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_STREAM): bound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  KTEST_BEGIN("bind(SOCK_STREAM): already bound socket");
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock));


  KTEST_BEGIN("bind(SOCK_STREAM): bind to bad address");
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  addr.sin_addr.s_addr = str2inet("0.0.0.1");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sin_addr.s_addr = str2inet("8.8.8.8");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  // Too-short address.
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr) - 5));


  KTEST_BEGIN("bind(SOCK_STREAM): wrong address family");
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));


  KTEST_BEGIN("bind(SOCK_STREAM): bad FD");
  addr.sin_family = AF_UNIX;
  addr.sin_addr.s_addr = str2inet("0.0.0.0");
  KEXPECT_EQ(-EBADF, net_bind(100, (struct sockaddr*)&addr, sizeof(addr)));

  vfs_close(sock);
}

static void multi_bind_test(void) {
  KTEST_BEGIN("bind(SOCK_STREAM): bind to already-bound address");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  int sock2 = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock2, 0);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  // TODO(tcp): enable this test (and others) when connect is implemented.
#if 0
  KTEST_BEGIN("bind(SOCK_STREAM): bind to already-bound and connected address");
  struct sockaddr_in connected_addr;
  connected_addr.sin_family = AF_INET;
  connected_addr.sin_addr.s_addr = str2inet("127.0.0.5");
  connected_addr.sin_port = 8888;
  KEXPECT_EQ(
      0, net_connect(sock, (struct sockaddr*)&connected_addr, sizeof(addr)));
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
#endif

  KTEST_BEGIN("bind(SOCK_STREAM): bind to INADDR_ANY on already-used port");
  addr.sin_addr.s_addr = INADDR_ANY;
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN(
      "bind(SOCK_STREAM): can bind to previously-used port after close");
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock2));
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  sock2 = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock2, 0);

  KTEST_BEGIN(
      "bind(SOCK_STREAM): bind to addr on already-used INADDR_ANY port");
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_STREAM): bind to port 0 (specific IP)");
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 0;
  KEXPECT_EQ(0, vfs_close(sock));
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  struct sockaddr_storage sockname_addr;
  char prettybuf[INET_PRETTY_LEN];
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1",
                inet2str(((struct sockaddr_in*)&sockname_addr)->sin_addr.s_addr,
                         prettybuf));
  in_port_t port1 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port1);

  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, net_getsockname(sock2, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1",
                inet2str(((struct sockaddr_in*)&sockname_addr)->sin_addr.s_addr,
                         prettybuf));
  in_port_t port2 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port2);
  KEXPECT_NE(port1, port2);

  // TODO(aoates): test binding to the same port on two different addresses.

  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(sock2));
}

void tcp_test(void) {
  KTEST_SUITE_BEGIN("TCP");
  const int initial_cache_size = vfs_cache_size();

  tcp_socket_test();
  sockopt_test();
  bind_test();
  multi_bind_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
