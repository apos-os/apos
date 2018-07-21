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
#include "dev/net/nic.h"
#include "memory/kmalloc.h"
#include "net/bind.h"
#include "net/ip/checksum.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/raw.h"
#include "net/socket/socket.h"
#include "net/util.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
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

  KTEST_BEGIN("Raw sockets: accept_queue_length() unsupported");
  KEXPECT_EQ(-EOPNOTSUPP, net_accept_queue_length(sock));

  KEXPECT_EQ(0, vfs_close(sock));
}

static void do_recv(void* arg) {
  char buf[200];
  int sock = *(int*)arg;
  proc_exit(net_recv(sock, buf, 200, 0));
}

// Helper to avoid having to specify the address each time.
static void do_ip_dispatch(const pbuf_t* pb, ethertype_t ethertype, int protocol) {
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = str2inet("1.2.3.4");
  addr.sin_port = 0;
  sock_raw_dispatch(pbuf_dup(pb, true), ethertype, protocol,
                    (struct sockaddr*)&addr, sizeof(addr));
}

static void recv_test(void) {
  KTEST_BEGIN("recv(SOCK_RAW): basic receive");
  int sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(sock, 0);

  pbuf_t* pb1 = pbuf_create(INET_HEADER_RESERVE, 3);
  kmemcpy(pbuf_get(pb1), "abc", 3);
  ip4_add_hdr(pb1, str2inet("1.2.3.4"), str2inet("5.6.7.8"), IPPROTO_ICMP);
  pbuf_t* pb2 = pbuf_create(INET_HEADER_RESERVE, 4);
  kmemcpy(pbuf_get(pb2), "defg", 4);
  ip4_add_hdr(pb2, str2inet("5.6.7.8"), str2inet("1.2.3.4"), IPPROTO_ICMP);

  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  do_ip_dispatch(pbuf_dup(pb2, true), ET_IPV4, IPPROTO_ICMP);

  char buf[200];
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, net_recv(sock, buf, 200, 0));
  KEXPECT_EQ(0, kmemcmp(buf, pbuf_getc(pb1), pbuf_size(pb1)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 4, net_recv(sock, buf, 200, 0));
  KEXPECT_EQ(0, kmemcmp(buf, pbuf_getc(pb2), pbuf_size(pb2)));


  KTEST_BEGIN("recv(SOCK_RAW): buffer too small");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  do_ip_dispatch(pbuf_dup(pb2, true), ET_IPV4, IPPROTO_ICMP);

  kmemset(buf, 0, 200);
  KEXPECT_EQ(10, net_recv(sock, buf, 10, 0));
  KEXPECT_EQ(0, kmemcmp(buf, pbuf_getc(pb1), 10));
  KEXPECT_EQ(0, kmemcmp(buf + 10, buf + 100, 10));  // Sdould still be zeroes.

  // Should get the next packet whole.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 4, net_recv(sock, buf, 200, 0));
  KEXPECT_EQ(0, kmemcmp(buf, pbuf_getc(pb2), pbuf_size(pb2)));


  KTEST_BEGIN("recv(SOCK_RAW): blocks until ready");
  int arg = sock;
  int result;
  pid_t child = proc_fork(&do_recv, &arg);
  ksleep(20);
  KEXPECT_EQ(0, proc_waitpid(child, &result, WNOHANG));
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  KEXPECT_EQ(child, proc_waitpid(child, &result, 0));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, result);


  KTEST_BEGIN("recv(SOCK_RAW): signal while blocking");
  arg = sock;
  child = proc_fork(&do_recv, &arg);
  ksleep(10);
  proc_force_signal(proc_get(child), SIGUSR1);
  KEXPECT_EQ(child, proc_waitpid(child, &result, 0));
  KEXPECT_EQ(-EINTR, result);


  KTEST_BEGIN("recv(SOCK_RAW): non-blocking read");
  int nonblock_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(nonblock_sock, 0);
  vfs_make_nonblock(nonblock_sock);
  KEXPECT_EQ(-EAGAIN, net_recv(nonblock_sock, buf, 200, 0));
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, net_recv(nonblock_sock, buf, 200, 0));


  KTEST_BEGIN("recv(SOCK_RAW): ignores mismatched ethertype packets");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_ARP, IPPROTO_ICMP);
  KEXPECT_EQ(-EAGAIN, net_recv(nonblock_sock, buf, 200, 0));


  KTEST_BEGIN("recv(SOCK_RAW): ignores mismatched protocol packets");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, 6);
  KEXPECT_EQ(-EAGAIN, net_recv(nonblock_sock, buf, 200, 0));


  KTEST_BEGIN("recv(SOCK_RAW): multiple matching raw sockets");
  int sock2 = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(sock2, 0);

  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, net_recv(sock, buf, 200, 0));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, net_recv(nonblock_sock, buf, 200, 0));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, net_recv(sock2, buf, 200, 0));
  KEXPECT_EQ(-EAGAIN, net_recv(nonblock_sock, buf, 200, 0));
  KEXPECT_EQ(0, vfs_close(sock2));


  KTEST_BEGIN("recvfrom(SOCK_RAW): basic test (sets address)");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  struct sockaddr_in addr;
  kmemset(&addr, 0xFF, sizeof(addr));
  socklen_t addrlen = sizeof(addr) * 2;
  KEXPECT_EQ(
      sizeof(ip4_hdr_t) + 3,
      net_recvfrom(sock, buf, 200, 0, (struct sockaddr*)&addr, &addrlen));
  KEXPECT_EQ(sizeof(addr), addrlen);
  KEXPECT_EQ(addr.sin_family, AF_INET);
  KEXPECT_EQ(addr.sin_port, 0);

  char prettybuf[INET_PRETTY_LEN];
  KEXPECT_STREQ("1.2.3.4", inet2str(addr.sin_addr.s_addr, prettybuf));


  KTEST_BEGIN("recvfrom(SOCK_RAW): NULL address parameters");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  addrlen = 123;
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3,
             net_recvfrom(sock, buf, 200, 0, NULL, &addrlen));
  KEXPECT_EQ(123, addrlen);

  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  addr.sin_family = 123;
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3,
             net_recvfrom(sock, buf, 200, 0, (struct sockaddr*)&addr, NULL));
  KEXPECT_EQ(123, addr.sin_family);


  KTEST_BEGIN("recvfrom(SOCK_RAW): address buffer too small");
  do_ip_dispatch(pbuf_dup(pb1, true), ET_IPV4, IPPROTO_ICMP);
  addr.sin_family = 123;
  addrlen = 10;
  KEXPECT_EQ(
      sizeof(ip4_hdr_t) + 3,
      net_recvfrom(sock, buf, 200, 0, (struct sockaddr*)&addr, &addrlen));
  KEXPECT_EQ(123, addr.sin_family);
  KEXPECT_EQ(10, addrlen);

  // TODO(aoates): more tests:
  //  - read()
  //  - flags set
  //  - interrupt-safe test
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(nonblock_sock));
  pbuf_free(pb1);
  pbuf_free(pb2);
}

static void bind_test(void) {
  KTEST_BEGIN("bind(SOCK_RAW): can bind to NIC's address");
  int sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));

  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));


  KTEST_BEGIN("bind(SOCK_RAW): already bound socket");
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock));


  KTEST_BEGIN("bind(SOCK_RAW): bind to bad address");
  sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  addr.sin_addr.s_addr = str2inet("0.0.0.0");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sin_addr.s_addr = str2inet("8.8.8.8");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  // Too-short address.
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr) - 5));


  KTEST_BEGIN("bind(SOCK_RAW): wrong address family");
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));


  KTEST_BEGIN("bind(SOCK_RAW): bad FD");
  addr.sin_family = AF_UNIX;
  addr.sin_addr.s_addr = str2inet("0.0.0.0");
  KEXPECT_EQ(-EBADF, net_bind(100, (struct sockaddr*)&addr, sizeof(addr)));

  vfs_close(sock);
}

static void sendto_test(void) {
  KTEST_BEGIN("sendto(SOCK_RAW): basic send");
  int send_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  int recv_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(send_sock, 0);
  KEXPECT_GE(recv_sock, 0);
  vfs_make_nonblock(recv_sock);

  // Send to localhost.  Not an easy way to further test the auto-bind code
  // without deeper hooks into the network code.
  struct sockaddr_in dst_addr;
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr.s_addr = str2inet("127.0.0.5");

  KEXPECT_EQ(3, net_sendto(send_sock, "abc", 3, 0, (struct sockaddr*)&dst_addr,
                           sizeof(dst_addr)));

  char buf[100];
  int result = net_recv(recv_sock, buf, 100, 0);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, result);
  buf[result] = '\0';

  ip4_hdr_t* hdr = (ip4_hdr_t*)buf;
  char prettybuf[INET_PRETTY_LEN];
  KEXPECT_STREQ("127.0.0.1", inet2str(hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.5", inet2str(hdr->dst_addr, prettybuf));
  KEXPECT_EQ(IPPROTO_ICMP, hdr->protocol);
  KEXPECT_EQ(0, ip_checksum(hdr, sizeof(ip4_hdr_t)));
  KEXPECT_STREQ(buf + sizeof(ip4_hdr_t), "abc");


  KTEST_BEGIN("sendto(SOCK_RAW): no address provided");
  KEXPECT_EQ(-EDESTADDRREQ,
             net_sendto(send_sock, "abc", 3, 0, NULL, sizeof(dst_addr)));
  KEXPECT_EQ(-EINVAL, net_sendto(send_sock, "abc", 3, 0,
                                 (struct sockaddr*)&dst_addr, 2));
  KEXPECT_EQ(-EDESTADDRREQ, net_send(send_sock, "abc", 3, 0));
  KEXPECT_EQ(-EDESTADDRREQ, vfs_write(send_sock, "abc", 3));
  KEXPECT_EQ(-EAGAIN, vfs_read(recv_sock, buf, 100));


  KTEST_BEGIN("sendto(SOCK_RAW): wrong address family");
  dst_addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_sendto(send_sock, "abc", 3, 0, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr)));
  dst_addr.sin_family = AF_INET;
  KEXPECT_EQ(-EAGAIN, vfs_read(recv_sock, buf, 100));


  KTEST_BEGIN("sendto(SOCK_RAW): bad flags");
  KEXPECT_EQ(-EINVAL,
             net_sendto(send_sock, "abc", 3, 3, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr)));
  KEXPECT_EQ(-EAGAIN, vfs_read(recv_sock, buf, 100));


  KTEST_BEGIN("sendto(SOCK_RAW): after bind");
  struct sockaddr_in bind_addr;
  netaddr_t bind_netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &bind_netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&bind_netaddr, 0, &bind_addr, sizeof(bind_addr)));
  KEXPECT_EQ(
      0, net_bind(send_sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)));
  KEXPECT_EQ(3, net_sendto(send_sock, "abc", 3, 0, (struct sockaddr*)&dst_addr,
                           sizeof(dst_addr)));

  result = net_recv(recv_sock, buf, 100, 0);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, result);

  char prettybuf2[INET_PRETTY_LEN];
  KEXPECT_STREQ(inet2str(bind_netaddr.a.ip4.s_addr, prettybuf),
                inet2str(hdr->src_addr, prettybuf2));
  KEXPECT_STREQ("127.0.0.5", inet2str(hdr->dst_addr, prettybuf));
  KEXPECT_EQ(IPPROTO_ICMP, hdr->protocol);
  KEXPECT_EQ(0, ip_checksum(hdr, sizeof(ip4_hdr_t)));


  // TODO(aoates): add test for sending to an address that's unreachable from
  // the bound address.)
  KEXPECT_EQ(0, vfs_close(send_sock));
  KEXPECT_EQ(0, vfs_close(recv_sock));
}

static void connect_test(void) {
  KTEST_BEGIN("connect(SOCK_RAW): basic connect() and send()");
  int send_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  int recv_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(send_sock, 0);
  KEXPECT_GE(recv_sock, 0);
  vfs_make_nonblock(recv_sock);

  struct sockaddr_in dst_addr;
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr.s_addr = str2inet("127.0.0.5");
  KEXPECT_EQ(
      0, net_connect(send_sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)));

  KEXPECT_EQ(3, net_send(send_sock, "abc", 3, 0));

  char buf[100];
  int result = net_recv(recv_sock, buf, 100, 0);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, result);
  buf[result] = '\0';
  ip4_hdr_t* hdr = (ip4_hdr_t*)buf;
  char prettybuf[INET_PRETTY_LEN];
  KEXPECT_STREQ("127.0.0.1", inet2str(hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.5", inet2str(hdr->dst_addr, prettybuf));
  KEXPECT_EQ(IPPROTO_ICMP, hdr->protocol);
  KEXPECT_EQ(0, ip_checksum(hdr, sizeof(ip4_hdr_t)));
  KEXPECT_STREQ(buf + sizeof(ip4_hdr_t), "abc");


  KTEST_BEGIN("connect(SOCK_RAW): already connected socket");
  KEXPECT_EQ(-EISCONN, net_connect(send_sock, (struct sockaddr*)&dst_addr,
                                   sizeof(dst_addr)));

  KTEST_BEGIN("connect(SOCK_RAW): sendto() with NULL address");
  KEXPECT_EQ(3, net_sendto(send_sock, "def", 3, 0, NULL, 0));
  result = net_recv(recv_sock, buf, 100, 0);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + 3, result);
  buf[result] = '\0';
  KEXPECT_STREQ("127.0.0.1", inet2str(hdr->src_addr, prettybuf));
  KEXPECT_STREQ("127.0.0.5", inet2str(hdr->dst_addr, prettybuf));
  KEXPECT_EQ(IPPROTO_ICMP, hdr->protocol);
  KEXPECT_EQ(0, ip_checksum(hdr, sizeof(ip4_hdr_t)));
  KEXPECT_STREQ(buf + sizeof(ip4_hdr_t), "def");


  KTEST_BEGIN("connect(SOCK_RAW): sendto() with address fails");
  KEXPECT_EQ(-EISCONN,
             net_sendto(send_sock, "def", 3, 0, (struct sockaddr*)&dst_addr,
                        sizeof(dst_addr)));
  KEXPECT_EQ(-EAGAIN, net_recv(recv_sock, buf, 100, 0));
  KEXPECT_EQ(0, vfs_close(send_sock));


  KTEST_BEGIN("connect(SOCK_RAW): wrong address family");
  send_sock = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  KEXPECT_GE(send_sock, 0);

  dst_addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT, net_connect(send_sock, (struct sockaddr*)&dst_addr,
                                        sizeof(dst_addr)));


  KTEST_BEGIN("connect(SOCK_RAW): bad addres");
  dst_addr.sin_family = AF_INET;
  KEXPECT_EQ(-EDESTADDRREQ, net_connect(send_sock, (struct sockaddr*)&dst_addr,
                                        sizeof(dst_addr) - 5));
  KEXPECT_EQ(-EDESTADDRREQ, net_connect(send_sock, NULL, sizeof(dst_addr)));

  // TODO(aoates): add test for connecting to an address that's unreachable from
  // the bound address.)
  KEXPECT_EQ(0, vfs_close(send_sock));
  KEXPECT_EQ(0, vfs_close(recv_sock));
}

void socket_raw_test(void) {
  KTEST_SUITE_BEGIN("Socket (raw)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  unsupported_ops_test();
  recv_test();
  bind_test();
  sendto_test();
  connect_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
