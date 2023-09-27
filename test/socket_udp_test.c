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

#include "common/endian.h"
#include "common/kprintf.h"
#include "memory/block_cache.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static void make_saddr(struct sockaddr_in* saddr, const char* addr, int port) {
  saddr->sin_family = AF_INET;
  saddr->sin_addr.s_addr = str2inet(addr);
  saddr->sin_port = htob16(port);
}

static int do_bind(int sock, const char* addr, int port) {
  struct sockaddr_in saddr;
  make_saddr(&saddr, addr, port);
  return net_bind(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

static int do_connect(int sock, const char* addr, int port) {
  struct sockaddr_in saddr;
  make_saddr(&saddr, addr, port);
  return net_connect(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

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

static void bind_test(void) {
  KTEST_BEGIN("bind(SOCK_DGRAM): can bind to NIC's address");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_port = 1234;

  KTEST_BEGIN("getsockname(SOCK_DGRAM): unbound socket");
  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_UNSPEC, result_addr->sin_family);

  KTEST_BEGIN("getpeername(SOCK_DGRAM): unbound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("getsockname(SOCK_DGRAM): bound socket");
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(addr.sin_addr.s_addr, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(1234, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_DGRAM): bound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  KTEST_BEGIN("bind(SOCK_DGRAM): already bound socket");
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock));


  KTEST_BEGIN("bind(SOCK_DGRAM): bind to bad address");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
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


  KTEST_BEGIN("bind(SOCK_DGRAM): wrong address family");
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));


  KTEST_BEGIN("bind(SOCK_DGRAM): bad FD");
  addr.sin_family = AF_UNIX;
  addr.sin_addr.s_addr = str2inet("0.0.0.0");
  KEXPECT_EQ(-EBADF, net_bind(100, (struct sockaddr*)&addr, sizeof(addr)));

  vfs_close(sock);
}

static void multi_bind_test(void) {
  KTEST_BEGIN("bind(SOCK_DGRAM): bind to already-bound address");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  int sock2 = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock2, 0);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_DGRAM): bind to already-bound and connected address");
  struct sockaddr_in connected_addr;
  connected_addr.sin_family = AF_INET;
  connected_addr.sin_addr.s_addr = str2inet("127.0.0.5");
  connected_addr.sin_port = 8888;
  KEXPECT_EQ(
      0, net_connect(sock, (struct sockaddr*)&connected_addr, sizeof(addr)));
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_DGRAM): bind to INADDR_ANY on already-used port");
  addr.sin_addr.s_addr = INADDR_ANY;
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_DGRAM): can bind to previously-used port after close");
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock2));
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  sock2 = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock2, 0);

  KTEST_BEGIN("bind(SOCK_DGRAM): bind to addr on already-used INADDR_ANY port");
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_DGRAM): bind to port 0 (specific IP)");
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 0;
  KEXPECT_EQ(0, vfs_close(sock));
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
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

static void connect_test(void) {
  char prettybuf[INET_PRETTY_LEN];
  KTEST_BEGIN("connect(SOCK_DGRAM): connect unbound socket");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in dst_addr;
  dst_addr.sin_family = AF_INET;

  dst_addr.sin_addr.s_addr = str2inet("1.2.3.4");
  dst_addr.sin_port = 1234;

  KEXPECT_EQ(0,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  // We should have implicitly bound the socket to INADDR_ANY and an unused
  // port.
  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_GE(btoh16(result_addr->sin_port), INET_PORT_EPHMIN);
  KEXPECT_LE(btoh16(result_addr->sin_port), INET_PORT_EPHMAX);
  in_port_t orig_bound_port = result_addr->sin_port;

  // getpeername() should give us the right peer.
  KTEST_BEGIN("getpeername(SOCK_DGRAM): connected socket");
  KEXPECT_EQ(0, net_getpeername(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("1.2.3.4", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(1234, result_addr->sin_port);


  KTEST_BEGIN("connect(SOCK_DGRAM): re-connect to new address");
  dst_addr.sin_addr.s_addr = str2inet("5.6.7.8");
  dst_addr.sin_port = 5678;

  KEXPECT_EQ(0,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(orig_bound_port, result_addr->sin_port);

  // getpeername() should give us the right peer.
  KEXPECT_EQ(0, net_getpeername(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("5.6.7.8", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(5678, result_addr->sin_port);

  KTEST_BEGIN(
      "connect(SOCK_DGRAM): connect to bad address (doesn't disconnect)");
  dst_addr.sin_family = AF_UNIX;

  KEXPECT_EQ(-EAFNOSUPPORT,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));
  dst_addr.sin_family = AF_INET;
  // Test too-short address.
  KEXPECT_EQ(-EDESTADDRREQ, net_connect(sock, (struct sockaddr*)&dst_addr,
                                        sizeof(dst_addr) - 5));

  // getpeername() should give us the same peer.
  KEXPECT_EQ(0, net_getpeername(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("5.6.7.8", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(5678, result_addr->sin_port);


  KTEST_BEGIN("connect(SOCK_DGRAM): connect to NULL address (disconnects)");
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr.s_addr = str2inet("5.6.7.8");
  dst_addr.sin_port = 5678;

  KEXPECT_EQ(0,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  dst_addr.sin_family = AF_UNSPEC;
  KEXPECT_EQ(0,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  vfs_close(sock);


  KTEST_BEGIN("connect(SOCK_DGRAM): connect bound socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in src_addr;
  src_addr.sin_family = AF_INET;
  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &src_addr, sizeof(src_addr)));
  src_addr.sin_port = 5678;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)));

  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr.s_addr = str2inet("1.2.3.4");
  dst_addr.sin_port = 1234;

  KEXPECT_EQ(0,
             net_connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(src_addr.sin_addr.s_addr, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(5678, result_addr->sin_port);

  KEXPECT_EQ(0, net_getpeername(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("1.2.3.4", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(1234, result_addr->sin_port);
  vfs_close(sock);
}

static void sendto_test(void) {
  KTEST_BEGIN("net_sendto(UDP): basic send");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  int recv_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  KEXPECT_GE(recv_sock, 0);

  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 1234));
  KEXPECT_EQ(0, do_connect(sock, "127.0.0.2", 5678));
  KEXPECT_EQ(3, net_sendto(sock, "abc", 3, 0, NULL, 0));

  char recv_buf[100];
  char prettybuf[INET_PRETTY_LEN];
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len = sizeof(recv_addr);
  int result = net_recvfrom(recv_sock, recv_buf, 100, 0,
                            (struct sockaddr*)&recv_addr, &recv_addr_len);
  KEXPECT_EQ(result, sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3);
  const ip4_hdr_t* ip_hdr = (ip4_hdr_t*)recv_buf;
  KEXPECT_EQ(0x45, ip_hdr->version_ihl);
  KEXPECT_EQ(0x0, ip_hdr->dscp_ecn);
  KEXPECT_EQ(result, btoh16(ip_hdr->total_len));
  KEXPECT_EQ(0, ip_hdr->id);
  KEXPECT_EQ(0, ip_hdr->flags_fragoff);
  KEXPECT_GE(ip_hdr->ttl, 10);
  KEXPECT_EQ(IPPROTO_UDP, ip_hdr->protocol);
  KEXPECT_EQ(0x7ccb, btoh16(ip_hdr->hdr_checksum));
  KEXPECT_STREQ("127.0.0.1", inet2str(ip_hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.2", inet2str(ip_hdr->dst_addr, prettybuf));

  const udp_hdr_t* udp_hdr = (udp_hdr_t*)&recv_buf[sizeof(ip4_hdr_t)];
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3, btoh16(udp_hdr->len));
  KEXPECT_EQ(0x2272, btoh16(udp_hdr->checksum));
  recv_buf[result] = '\0';
  KEXPECT_STREQ("abc", &recv_buf[sizeof(ip4_hdr_t) + sizeof(udp_hdr_t)]);

  KTEST_BEGIN("net_sendto(UDP): packet with all-zeroes checksum");
  KEXPECT_EQ(2, net_sendto(sock, "\xe6\xd6", 2, 0, NULL, 0));

  result = net_recvfrom(recv_sock, recv_buf, 100, 0, NULL, NULL);
  KEXPECT_EQ(result, sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 2);
  udp_hdr = (udp_hdr_t*)&recv_buf[sizeof(ip4_hdr_t)];
  KEXPECT_EQ(0xffff, btoh16(udp_hdr->checksum));

  KTEST_BEGIN("net_sendto(UDP): address on connected socket");
  struct sockaddr_in dst_addr;
  KEXPECT_EQ(-EISCONN,
             net_sendto(sock, "abc", 3, 0, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr)));
  vfs_close(sock);

  KTEST_BEGIN("net_sendto(UDP): send on unconnected socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 1234));
  make_saddr(&dst_addr, "127.0.0.3", 7890);
  KEXPECT_EQ(3, net_sendto(sock, "def", 3, 0, (struct sockaddr*)&dst_addr,
                           sizeof(dst_addr)));
  result = net_recvfrom(recv_sock, recv_buf, 100, 0,
                        (struct sockaddr*)&recv_addr, &recv_addr_len);
  KEXPECT_EQ(result, sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3);
  KEXPECT_STREQ("127.0.0.1", inet2str(ip_hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.3", inet2str(ip_hdr->dst_addr, prettybuf));
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(7890, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("def", &recv_buf[sizeof(ip4_hdr_t) + sizeof(udp_hdr_t)]);

  KTEST_BEGIN("net_sendto(UDP): send without addr on unconnected socket");
  KEXPECT_EQ(-EDESTADDRREQ, net_sendto(sock, "def", 3, 0, NULL, 0));

  KTEST_BEGIN("net_sendto(UDP): send to wrong address family");
  dst_addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_sendto(sock, "def", 3, 0, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr)));

  KTEST_BEGIN("net_sendto(UDP): send to too-short address");
  dst_addr.sin_family = AF_INET;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_sendto(sock, "abc", 3, 0, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr) - 1));
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_sendto(sock, "abc", 3, 0, (struct sockaddr*)0x01,
                        sizeof(dst_addr) - 1));
  KEXPECT_EQ(-EINVAL, net_sendto(sock, "abc", 3, 0, (struct sockaddr*)0x01, 3));
  KEXPECT_EQ(-EINVAL, net_sendto(sock, "abc", 3, 0, (struct sockaddr*)0x01, 0));
  KEXPECT_EQ(-EINVAL,
             net_sendto(sock, "abc", 3, 0, (struct sockaddr*)0x01, -1));

  vfs_close(sock);


  KTEST_BEGIN("net_sendto(UDP): send on socket bound to INADDR_ANY");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "0.0.0.0", 1234));
  KEXPECT_EQ(3, net_sendto(sock, "XYZ", 3, 0, (struct sockaddr*)&dst_addr,
                           sizeof(dst_addr)));

  result = net_recvfrom(recv_sock, recv_buf, 100, 0,
                        (struct sockaddr*)&recv_addr, &recv_addr_len);
  KEXPECT_EQ(result, sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3);
  KEXPECT_STREQ("127.0.0.1", inet2str(ip_hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.3", inet2str(ip_hdr->dst_addr, prettybuf));
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(7890, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("XYZ", &recv_buf[sizeof(ip4_hdr_t) + sizeof(udp_hdr_t)]);
  vfs_close(sock);


  KTEST_BEGIN("net_sendto(UDP): send on unbound socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(3, net_sendto(sock, "XYZ", 3, 0, (struct sockaddr*)&dst_addr,
                           sizeof(dst_addr)));

  // We should have implicitly bound the socket to INADDR_ANY and an unused
  // port.
  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", inet2str(result_addr->sin_addr.s_addr, prettybuf));
  KEXPECT_GE(btoh16(result_addr->sin_port), INET_PORT_EPHMIN);
  KEXPECT_LE(btoh16(result_addr->sin_port), INET_PORT_EPHMAX);
  in_port_t orig_bound_port = btoh16(result_addr->sin_port);

  result = net_recvfrom(recv_sock, recv_buf, 100, 0,
                        (struct sockaddr*)&recv_addr, &recv_addr_len);
  KEXPECT_EQ(result, sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3);
  KEXPECT_STREQ("127.0.0.1", inet2str(ip_hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.3", inet2str(ip_hdr->dst_addr, prettybuf));
  KEXPECT_EQ(orig_bound_port, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(7890, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("XYZ", &recv_buf[sizeof(ip4_hdr_t) + sizeof(udp_hdr_t)]);

  vfs_close(recv_sock);
  vfs_close(sock);
}

static void do_recv(void* arg) {
  char buf[200];
  int sock = *(int*)arg;
  proc_exit(net_recv(sock, buf, 200, 0));
}

static void recvfrom_test(void) {
  KTEST_BEGIN("net_recvfrom(UDP): basic recv");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  vfs_make_nonblock(sock);

  int raw_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  KEXPECT_GE(raw_sock, 0);

  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 1234));

  char send_buf[100];
  udp_hdr_t* udp_hdr = (udp_hdr_t*)send_buf;
  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 3);
  udp_hdr->checksum = htob16(0x2273);
  kstrcpy(&send_buf[sizeof(udp_hdr_t)], "abc");
  struct sockaddr_in send_addr;
  send_addr.sin_family = AF_INET;
  send_addr.sin_addr.s_addr = str2inet("127.0.0.1");
  send_addr.sin_port = htob16(1234);
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  kstrcpy(&send_buf[sizeof(udp_hdr_t)], "def");
  udp_hdr->checksum = htob16(0x1c70);
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));

  char recv_buf[100];
  char prettybuf[INET_PRETTY_LEN];
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len = sizeof(recv_addr);
  KEXPECT_EQ(3, net_recvfrom(sock, recv_buf, 10, 0,
                             (struct sockaddr*)&recv_addr, &recv_addr_len));
  KEXPECT_EQ(sizeof(recv_addr), recv_addr_len);
  KEXPECT_EQ(AF_INET, recv_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", inet2str(recv_addr.sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(5678, btoh16(recv_addr.sin_port));
  recv_buf[3] = '\0';
  KEXPECT_STREQ("abc", recv_buf);

  KEXPECT_EQ(3, net_recvfrom(sock, recv_buf, 10, 0,
                             (struct sockaddr*)&recv_addr, &recv_addr_len));
  KEXPECT_STREQ("def", recv_buf);

  // The packet should not have been dispatched to the raw socket.
  vfs_make_nonblock(raw_sock);
  KEXPECT_EQ(-EAGAIN, net_recvfrom(raw_sock, recv_buf, 10, 0, NULL, NULL));

  KTEST_BEGIN("net_recvfrom(UDP): sendto()/recvfrom() paired");
  int send_sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(send_sock, 0);
  KEXPECT_EQ(0, do_bind(send_sock, "127.0.0.1", 1122));
  KEXPECT_EQ(0, do_connect(send_sock, "127.0.0.1", 1234));

  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  recv_addr_len = sizeof(recv_addr);
  KEXPECT_EQ(3, net_recvfrom(sock, recv_buf, 10, 0,
                             (struct sockaddr*)&recv_addr, &recv_addr_len));
  KEXPECT_EQ(sizeof(recv_addr), recv_addr_len);
  KEXPECT_EQ(AF_INET, recv_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", inet2str(recv_addr.sin_addr.s_addr, prettybuf));
  KEXPECT_EQ(1122, btoh16(recv_addr.sin_port));
  recv_buf[3] = '\0';
  KEXPECT_STREQ("123", recv_buf);


  KTEST_BEGIN("net_recvfrom(UDP): medium-sized packet");
  KEXPECT_EQ(100, net_sendto(send_sock, recv_buf, 100, 0, NULL, 0));
  KEXPECT_EQ(100, net_recvfrom(sock, recv_buf, 100, 0, NULL, NULL));


  KTEST_BEGIN("net_recvfrom(UDP): packet with truncated UDP header");
  KEXPECT_EQ(3, net_sendto(raw_sock, send_buf, /* too-short packet length */ 3,
                           0, (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet with too-small len in UDP header");
  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) - 1);
  udp_hdr->checksum = htob16(0x1c78);
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet with too-large len in UDP header");
  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(100);  // Larger than underlying packet.
  udp_hdr->checksum = htob16(0x1bbe);
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));

  // This time use a length that's longer than the data portion of the IP packet
  // but within the bounds of the packet itself.
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 3 + 1);
  udp_hdr->checksum = 0;
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet with smaller UDP len than IP len");
  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 1);
  udp_hdr->checksum = htob16(0x6ed9);
  kstrcpy(&send_buf[sizeof(udp_hdr_t)], "xyz");
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  // This should be valid, and we should get the UDP-reported length (ignoring
  // any extra data at the end).
  kmemset(recv_buf, 0, 10);
  KEXPECT_EQ(1, vfs_read(sock, recv_buf, 100));
  KEXPECT_STREQ("x", recv_buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet with bad UDP checksum");
  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 3);
  udp_hdr->checksum = htob16(0x1234);
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(-EAGAIN, vfs_read(sock, recv_buf, 100));
  KEXPECT_LT(0, vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet with disabled (zero) checksum");
  udp_hdr->checksum = 0;
  KEXPECT_EQ(sizeof(udp_hdr_t) + 3,
             net_sendto(raw_sock, send_buf, sizeof(udp_hdr_t) + 3, 0,
                        (struct sockaddr*)&send_addr, sizeof(send_addr)));
  KEXPECT_EQ(3, vfs_read(sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): packet received after socket closed");
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): receive on connected socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  vfs_make_nonblock(sock);
  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 1234));
  KEXPECT_EQ(0, do_connect(sock, "127.0.0.1", 1122));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(3, vfs_read(sock, recv_buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(raw_sock, recv_buf, 100));

  // If connected to a different port, should _not_ be received.
  KEXPECT_EQ(0, do_connect(sock, "127.0.0.1", 1123));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(-EAGAIN, vfs_read(sock, recv_buf, 100));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));

  // If connected to a different address, should _not_ be received.
  KEXPECT_EQ(0, do_connect(sock, "127.0.0.2", 1122));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(-EAGAIN, vfs_read(sock, recv_buf, 100));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(raw_sock, recv_buf, 100));
  KEXPECT_EQ(0, vfs_close(sock));


  KTEST_BEGIN("net_recvfrom(UDP): receive on unbound socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  vfs_make_nonblock(sock);
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(-EAGAIN, vfs_read(sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): receive on INADDR_ANY socket");
  KEXPECT_EQ(0, do_bind(sock, "0.0.0.0", 1234));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(3, vfs_read(sock, recv_buf, 100));


  KTEST_BEGIN("net_recvfrom(UDP): data buffer too small");
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  kmemset(recv_buf, 0, 10);
  KEXPECT_EQ(2, net_recvfrom(sock, recv_buf, 2, 0, NULL, NULL));
  KEXPECT_STREQ("12", recv_buf);


  KTEST_BEGIN("net_recvfrom(UDP): address buffer too small");
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  recv_addr_len = sizeof(sa_family_t) + sizeof(in_port_t);
  kmemset(&recv_addr, 0, sizeof(recv_addr));
  kmemset(recv_buf, 0, 10);
  KEXPECT_EQ(3, net_recvfrom(sock, recv_buf, 10, 0,
                             (struct sockaddr*)&recv_addr, &recv_addr_len));
  KEXPECT_STREQ("123", recv_buf);
  KEXPECT_EQ(AF_INET, recv_addr.sin_family);
  KEXPECT_EQ(btoh16(1122), recv_addr.sin_port);
  KEXPECT_EQ(0, recv_addr.sin_addr.s_addr);


  KTEST_BEGIN("net_recvfrom(UDP): blocks until data available");
  KEXPECT_EQ(0, vfs_close(sock));
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 1234));

  int arg = sock;
  int result;
  kpid_t child = proc_fork(&do_recv, &arg);
  ksleep(20);
  KEXPECT_EQ(0, proc_waitpid(child, &result, WNOHANG));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(2, net_sendto(send_sock, "45", 2, 0, NULL, 0));
  KEXPECT_EQ(child, proc_waitpid(child, &result, 0));
  KEXPECT_EQ(3, result);
  KEXPECT_EQ(2, net_recvfrom(sock, recv_buf, 10, 0, NULL, NULL));


  KTEST_BEGIN(
      "net_recvfrom(UDP): blocks until data available (multiple waiters)");
  child = proc_fork(&do_recv, &arg);
  kpid_t child2 = proc_fork(&do_recv, &arg);
  ksleep(20);
  KEXPECT_EQ(0, proc_waitpid(child, &result, WNOHANG));
  KEXPECT_EQ(0, proc_waitpid(child2, &result, WNOHANG));
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  kpid_t done_child = proc_waitpid(-1, &result, 0);
  KEXPECT_EQ(true, done_child == child || done_child == child2);
  kpid_t other_child = (done_child == child) ? child2 : child;
  KEXPECT_EQ(0, proc_waitpid(-1, &result, WNOHANG));
  KEXPECT_EQ(2, net_sendto(send_sock, "45", 2, 0, NULL, 0));
  KEXPECT_EQ(other_child, proc_waitpid(other_child, &result, 0));
  KEXPECT_EQ(2, result);


  KTEST_BEGIN("recv(SOCK_RAW): signal while blocking");
  arg = sock;
  child = proc_fork(&do_recv, &arg);
  ksleep(10);
  proc_force_signal(proc_get(child), SIGUSR1);
  KEXPECT_EQ(child, proc_waitpid(child, &result, 0));
  KEXPECT_EQ(-EINTR, result);


  KTEST_BEGIN("net_recvfrom(UDP): cleanup of unrecv'd packets");
  KEXPECT_EQ(3, net_sendto(send_sock, "123", 3, 0, NULL, 0));
  KEXPECT_EQ(3, net_sendto(send_sock, "456", 3, 0, NULL, 0));
  KEXPECT_EQ(3, net_sendto(send_sock, "789", 3, 0, NULL, 0));
  KEXPECT_EQ(0, vfs_close(sock));


  KEXPECT_EQ(0, vfs_close(send_sock));
  KEXPECT_EQ(0, vfs_close(raw_sock));
}

static void* do_poll_helper(void* arg) {
  struct apos_pollfd pfd;
  pfd.fd = *(int*)arg;
  pfd.revents = 0;
  pfd.events = KPOLLIN;
  void* result = (void*)(intptr_t)vfs_poll(&pfd, 1, 1000);
  KEXPECT_EQ(KPOLLIN, pfd.revents);
  return result;
}

static void* deferred_close(void* arg) {
  int fd = *(int*)arg;
  ksleep(50);
  KEXPECT_EQ(0, vfs_close(fd));
  return 0;
}

static void recv_poll_test(void) {
  KTEST_BEGIN("vfs_poll(UDP): KPOLLIN on empty socket");
  int send_sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  int recv_sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(send_sock, 0);
  KEXPECT_GE(recv_sock, 0);

  KEXPECT_EQ(0, do_bind(recv_sock, "0.0.0.0", 1234));
  KEXPECT_EQ(0, do_connect(send_sock, "127.0.0.1", 1234));

  struct apos_pollfd pfd;
  pfd.fd = recv_sock;
  pfd.revents = 0;
  pfd.events = KPOLLIN;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 10));


  KTEST_BEGIN("vfs_poll(UDP): KPOLLIN on readable socket");
  KEXPECT_EQ(3, net_sendto(send_sock, "abc", 3, 0, NULL, 0));
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 10));

  char buf[100];
  KEXPECT_EQ(3, net_recv(recv_sock, buf, 100, 0));


  KTEST_BEGIN("vfs_poll(UDP): blocking for KPOLLIN on readable socket");
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll_helper, &recv_sock));
  // Make sure we get good and stuck in vfs_poll()
  for (int i = 0; i < 20; ++i) scheduler_yield();
  KEXPECT_NE(NULL, thread->queue);

  KEXPECT_EQ(3, net_sendto(send_sock, "abc", 3, 0, NULL, 0));
  KEXPECT_EQ(1, (intptr_t)kthread_join(thread));
  KEXPECT_EQ(3, net_recv(recv_sock, buf, 100, 0));


  KTEST_BEGIN("vfs_poll(UDP): KPOLLOUT on socket");
  pfd.events = KPOLLIN | KPOLLOUT;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(KPOLLOUT, pfd.revents);


  KTEST_BEGIN("vfs_poll(UDP): underlying socket closed during poll");
  KEXPECT_EQ(0, proc_thread_create(&thread, &deferred_close, &recv_sock));

  pfd.events = KPOLLIN;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 1000));
  KEXPECT_EQ(KPOLLNVAL, pfd.revents);

  KEXPECT_EQ(0, (intptr_t)kthread_join(thread));

  KEXPECT_EQ(0, vfs_close(send_sock));
}

static void shutdown_test(void) {
  KTEST_BEGIN("net_shutdown(UDP): shutdown on unconnected UDP socket");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("net_shutdown(UDP): shutdown on connected UDP socket");
  sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_connect(sock, "127.0.0.1", 1234));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(sock));
}

static void sockopt_test(void) {
  KTEST_BEGIN("UDP socket: getsockopt");
  int sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  int val[2];
  socklen_t vallen = sizeof(int) * 2;
  KEXPECT_EQ(0, net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(SOCK_DGRAM, val[0]);

  KEXPECT_EQ(-ENOPROTOOPT,
             net_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val[0], &vallen));

  KTEST_BEGIN("UDP socket: getsockopt(SO_TYPE) option too small");
  vallen = 3;
  KEXPECT_EQ(-ENOMEM,
             net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  vallen = 0;
  KEXPECT_EQ(-ENOMEM,
             net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  vallen = -1;
  KEXPECT_EQ(-ENOMEM,
             net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  vallen = INT_MIN;
  KEXPECT_EQ(-ENOMEM,
             net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  vallen = sizeof(int) * 2;

  KTEST_BEGIN("UDP socket: setsockopt");
  KEXPECT_EQ(-ENOPROTOOPT,
             net_setsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], vallen));

  KTEST_BEGIN("getsockopt(): not a socket");
  int fd = vfs_open("/", VFS_O_DIRECTORY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-ENOTSOCK,
             net_getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val[0], &vallen));

  KTEST_BEGIN("setsockopt(): not a socket");
  KEXPECT_EQ(-ENOTSOCK,
             net_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val[0], vallen));

  KTEST_BEGIN("getsockopt(): bad FD");
  KEXPECT_EQ(-EBADF,
             net_getsockopt(-1, SOL_SOCKET, SO_RCVBUF, &val[0], &vallen));
  KEXPECT_EQ(-EBADF,
             net_getsockopt(1000, SOL_SOCKET, SO_RCVBUF, &val[0], &vallen));

  KTEST_BEGIN("setsockopt(): bad FD");
  KEXPECT_EQ(-EBADF,
             net_setsockopt(-1, SOL_SOCKET, SO_RCVBUF, &val[0], vallen));
  KEXPECT_EQ(-EBADF,
             net_setsockopt(1000, SOL_SOCKET, SO_RCVBUF, &val[0], vallen));

  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(fd));
}

void socket_udp_test(void) {
  KTEST_SUITE_BEGIN("Socket (UDP)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  unsupported_ops_test();
  bind_test();
  multi_bind_test();
  connect_test();
  sendto_test();
  recvfrom_test();
  recv_poll_test();
  shutdown_test();
  sockopt_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
