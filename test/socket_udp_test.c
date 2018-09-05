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

#include "arch/common/endian.h"
#include "common/kprintf.h"
#include "memory/block_cache.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/udp.h"
#include "net/util.h"
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
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_sendto(sock, "abc", 3, 0, (struct sockaddr*)0x01, 3));
  KEXPECT_EQ(-EAFNOSUPPORT,
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

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
