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

#include "common/endian.h"
#include "common/kassert.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/ip/checksum.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/socket.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/protocol.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

// Some helpers just to make tests clearer to read and eliminate lots of silly
// casting of sockaddr structs.
static const char* ip2str(in_addr_t addr) {
  static char buf[INET_PRETTY_LEN];
  return inet2str(addr, buf);
}

static const char* sas_ip2str(const struct sockaddr_storage* sas) {
  KASSERT(sas->sa_family == AF_INET);
  return ip2str(((struct sockaddr_in*)sas)->sin_addr.s_addr);
}

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

static tcp_key_t tcp_key_sin(const struct sockaddr_in* a,
                             const struct sockaddr_in* b) {
  return tcp_key((const struct sockaddr*)a, (const struct sockaddr*)b);
}

static void tcp_key_test(void) {
  KTEST_BEGIN("TCP key test (AF_INET)");
  struct sockaddr_in src1, src2, dst1, dst2;
  kmemset(&src1, 0xaa, sizeof(src1));
  kmemset(&src2, 0xbb, sizeof(src2));
  kmemset(&dst1, 0xcc, sizeof(dst1));
  kmemset(&dst2, 0xdd, sizeof(dst2));
  src1.sin_family = src2.sin_family = dst1.sin_family = dst2.sin_family =
      AF_INET;
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  src1.sin_addr.s_addr = str2inet("10.0.1.1");
  src1.sin_port = 1;
  dst1.sin_addr.s_addr = str2inet("10.0.1.2");
  dst1.sin_port = 2;
  src2.sin_addr.s_addr = str2inet("10.0.1.1");
  src2.sin_port = 1;
  dst2.sin_addr.s_addr = str2inet("10.0.1.2");
  dst2.sin_port = 2;
  KEXPECT_EQ(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  KEXPECT_EQ(tcp_key_sin(&src2, &dst1), tcp_key_sin(&src1, &dst2));
  KEXPECT_EQ(tcp_key_sin(&src1, &dst2), tcp_key_sin(&src2, &dst1));

  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&dst1, &src1));

  src1 = src2;
  src1.sin_port = 2;
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  src1 = src2;
  src1.sin_addr.s_addr = str2inet("10.0.1.2");
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
}

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
  KTEST_BEGIN("getsockname(SOCK_STREAM): unbound socket");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_UNSPEC, result_addr->sin_family);

  KTEST_BEGIN("getpeername(SOCK_STREAM): unbound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));


  KTEST_BEGIN("bind(SOCK_STREAM): can bind to NIC's address");
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_port = 1234;

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
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1", sas_ip2str(&sockname_addr));
  in_port_t port1 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port1);

  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, net_getsockname(sock2, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1", sas_ip2str(&sockname_addr));
  in_port_t port2 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port2);
  KEXPECT_NE(port1, port2);

  // TODO(aoates): test binding to the same port on two different addresses.

  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(sock2));
}

#define RAW_RECV_BUF_SIZE 100

typedef struct {
  kthread_t thread;
  int socket;
  int op_result;
  notification_t op_started;
  notification_t op_done;

  // Address of the TCP socket under test.
  const char* tcp_addr_str;
  struct sockaddr_in tcp_addr;

  // Raw socket and buffer for the "other side".
  const char* raw_addr_str;
  struct sockaddr_in raw_addr;
  int raw_socket;
  char recv[RAW_RECV_BUF_SIZE];

  const char* arg_addr;
  int arg_port;
} tcp_test_state_t;

// Creates and initializes the test state.  Does _not_ bind the test socket.
static void init_tcp_test(tcp_test_state_t* s, const char* tcp_addr,
                          int tcp_port, const char* dst_addr, int dst_port) {
  s->socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s->socket, 0);

  int initial_seq = 100;
  KEXPECT_EQ(0, net_setsockopt(s->socket, IPPROTO_TCP, SO_TCP_SEQ_NUM,
                               &initial_seq, sizeof(initial_seq)));

  s->tcp_addr_str = tcp_addr;
  make_saddr(&s->tcp_addr, tcp_addr, tcp_port);

  // Create the raw socket that will converse with the TCP socket under test.
  s->raw_socket = net_socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  KEXPECT_GE(s->raw_socket, 0);

  s->raw_addr_str = dst_addr;
  make_saddr(&s->raw_addr, dst_addr, dst_port);
  KEXPECT_EQ(0, net_bind(s->raw_socket, (struct sockaddr*)&s->raw_addr,
                         sizeof(s->raw_addr)));
}

static void* tcp_thread_connect(void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  ntfn_notify(&s->op_started);
  s->op_result = do_connect(s->socket, s->arg_addr, s->arg_port);
  ntfn_notify(&s->op_done);
  return NULL;
}

#define KEXPECT_TRUE_OR_RETURN(_x) \
  do {                             \
    bool _result = (_x);           \
    KEXPECT_TRUE(_result);         \
    if (!_result) return false;    \
  } while (0)

static bool start_connect(tcp_test_state_t* s, const char* ip, int port) {
  ntfn_init(&s->op_started);
  ntfn_init(&s->op_done);
  s->arg_addr = ip;
  s->arg_port = port;
  KEXPECT_EQ(0, proc_thread_create(&s->thread, &tcp_thread_connect, s));
  KEXPECT_TRUE_OR_RETURN(ntfn_await_with_timeout(&s->op_started, 5000));
  if (ntfn_await_with_timeout(&s->op_done, 20)) {
    KTEST_ADD_FAILURE("connect() finished without blocking");
    KEXPECT_EQ(0, s->op_result);  // Get the error code.
    return false;
  }
  return true;
}

static int finish_op(tcp_test_state_t* s) {
  bool finished = ntfn_await_with_timeout(&s->op_done, 5000);
  KEXPECT_EQ(true, finished);
  if (!finished) return -ETIMEDOUT;

  KEXPECT_EQ(NULL, kthread_join(s->thread));
  s->thread = NULL;
  return s->op_result;
}

static bool raw_has_packets(tcp_test_state_t* s) {
  struct apos_pollfd pfd;
  pfd.events = KPOLLIN;
  pfd.fd = s->raw_socket;
  int result = vfs_poll(&pfd, 1, 0);
  KASSERT(result >= 0);
  return (result > 0);
}

static ssize_t do_raw_recv(tcp_test_state_t* s) {
  if (!raw_has_packets(s)) {
    KTEST_ADD_FAILURE("Raw socket has no packets available");
    return -EAGAIN;
  }
  kmemset(s->recv, 0, RAW_RECV_BUF_SIZE);
  return net_recvfrom(s->raw_socket, s->recv, RAW_RECV_BUF_SIZE, 0, NULL, NULL);
}

static ssize_t do_raw_send(tcp_test_state_t* s, const void* buf, size_t len) {
  return net_sendto(s->raw_socket, buf, len, 0, (struct sockaddr*)&s->tcp_addr,
                    sizeof(s->tcp_addr));
}

// Special value to indicate a zero window size (since passing zero means
// "ignore").
#define WNDSIZE_ZERO 0xabcd

// Specification for a packet to expect or send.  Fields not supplied are not
// checked (on receive), or given default values (on send).
typedef struct {
  int flags;
  uint32_t seq;
  uint32_t ack;
  int wndsize;
} test_packet_spec_t;

static test_packet_spec_t SYN_PKT(int seq, int wndsize) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_SYN, .seq = seq, .wndsize = wndsize});
}

static test_packet_spec_t SYNACK_PKT(int seq, int ack, int wndsize) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_SYN | TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .wndsize = wndsize});
}

static test_packet_spec_t ACK_PKT(int seq, int ack) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_ACK, .seq = seq, .ack = ack});
}

static test_packet_spec_t FIN_PKT(int seq, int ack) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_FIN | TCP_FLAG_ACK, .seq = seq, .ack = ack});
}

#define EXPECT_PKT(_state, _spec) KEXPECT_TRUE(receive_pkt((_state), (_spec)));
#define SEND_PKT(_state, _spec) KEXPECT_TRUE(send_pkt((_state), (_spec)));

// Expects to receive a packet matching the given description, returning true if
// it does.
static bool receive_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  KEXPECT_TRUE_OR_RETURN(raw_has_packets(s));

  bool v = true;
  int result = do_raw_recv(s);
  v &= KEXPECT_GE(result, 0);
  if (!v) return v;

  // Validate the IP header.
  v &= KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  if (!v) return v;

  ip4_hdr_t* ip_hdr = (ip4_hdr_t*)s->recv;
  v &= KEXPECT_EQ(0x45, ip_hdr->version_ihl);
  v &= KEXPECT_EQ(0x0, ip_hdr->dscp_ecn);
  v &= KEXPECT_EQ(result, btoh16(ip_hdr->total_len));
  v &= KEXPECT_EQ(0, ip_hdr->id);
  v &= KEXPECT_EQ(0, ip_hdr->flags_fragoff);
  v &= KEXPECT_GE(ip_hdr->ttl, 10);
  v &= KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  // Don't bother checking the checksum here.
  v &= KEXPECT_STREQ(s->tcp_addr_str, ip2str(ip_hdr->src_addr));
  v &= KEXPECT_STREQ(s->raw_addr_str, ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)&s->recv[sizeof(ip4_hdr_t)];
  v &= KEXPECT_EQ(btoh16(s->tcp_addr.sin_port), btoh16(tcp_hdr->src_port));
  v &= KEXPECT_EQ(btoh16(s->raw_addr.sin_port), btoh16(tcp_hdr->dst_port));
  if (spec.seq != 0) {
    v &= KEXPECT_EQ(spec.seq, btoh32(tcp_hdr->seq));
  }
  if (spec.ack != 0) {
    v &= KEXPECT_EQ(spec.ack, btoh32(tcp_hdr->ack));
  }
  v &= KEXPECT_EQ(0, tcp_hdr->_zeroes);
  v &= KEXPECT_EQ(5, tcp_hdr->data_offset);
  v &= KEXPECT_EQ(spec.flags, tcp_hdr->flags);
  if (btoh16(tcp_hdr->wndsize) == 0 && spec.wndsize == 0) {
    KTEST_ADD_FAILURE("Must use WNDSIZE_ZERO when receiving a zero wndsize");
    v = false;
  }
  if (spec.wndsize != 0) {
    v &= KEXPECT_EQ(spec.wndsize == WNDSIZE_ZERO ? 0 : spec.wndsize,
                        btoh16(tcp_hdr->wndsize));
  }
  // Don't bother checking this checksum either.
  v &= KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));
  return v;
}

// Builds a packet based on the given spec and sends it.
static bool send_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  ip4_pseudo_hdr_t pseudo_ip;

  size_t tcp_len = sizeof(tcp_hdr_t);
  pseudo_ip.src_addr = s->raw_addr.sin_addr.s_addr;
  pseudo_ip.dst_addr = s->tcp_addr.sin_addr.s_addr;
  pseudo_ip.zeroes = 0;
  pseudo_ip.protocol = IPPROTO_TCP;
  pseudo_ip.length = btoh16(tcp_len);

  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)s->recv;
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = s->raw_addr.sin_port;
  tcp_hdr->dst_port = s->tcp_addr.sin_port;
  tcp_hdr->seq = btoh32(spec.seq);
  tcp_hdr->ack = (spec.flags & TCP_FLAG_ACK) ? btoh32(spec.ack) : 0;
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = spec.flags;
  tcp_hdr->wndsize = spec.wndsize;
  tcp_hdr->checksum = 0;

  tcp_hdr->checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip), tcp_hdr, tcp_len);
  return KEXPECT_EQ(tcp_len, do_raw_send(s, tcp_hdr, tcp_len));
}

static void basic_connect_test(void) {
  KTEST_BEGIN("TCP: basic connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Should have received a SYN.
  int result = do_raw_recv(&s);

  // Validate the IP header.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  ip4_hdr_t* ip_hdr = (ip4_hdr_t*)s.recv;
  KEXPECT_EQ(0x45, ip_hdr->version_ihl);
  KEXPECT_EQ(0x0, ip_hdr->dscp_ecn);
  KEXPECT_EQ(result, btoh16(ip_hdr->total_len));
  KEXPECT_EQ(0, ip_hdr->id);
  KEXPECT_EQ(0, ip_hdr->flags_fragoff);
  KEXPECT_GE(ip_hdr->ttl, 10);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_EQ(0x7cce, btoh16(ip_hdr->hdr_checksum));
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)&s.recv[sizeof(ip4_hdr_t)];
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(100, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_SYN, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0x08d0, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Send SYN-ACK back.  Raw socket will make the IP header for us.
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1000);
  tcp_hdr->ack = btoh32(101);
  tcp_hdr->checksum = 0x7f19;
  tcp_hdr->flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
  tcp_hdr->wndsize = btoh16(8000);
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));

  // Should get an ACK.
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1001, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8bf, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // TODO(tcp): exchange some data in both directions.

  // Send a FIN.
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1001);
  tcp_hdr->ack = btoh32(101);
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
  tcp_hdr->wndsize = 8000;
  tcp_hdr->checksum = 0x9ff8;

  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));

  // Should get an ACK.
  KEXPECT_TRUE(raw_has_packets(&s));
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->dst_addr));

  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1002, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8be, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // TODO(tcp): verify that read() returns 0/EOF.

  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1002, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_FIN | TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8bd, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Send final ack.
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1002);
  tcp_hdr->ack = btoh32(102);
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = TCP_FLAG_ACK;
  tcp_hdr->wndsize = 8000;
  tcp_hdr->checksum = 0x9ef8;
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));

  // TODO(tcp): test other operations on the socket now that its closed.

  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_EQ(0, vfs_close(s.raw_socket));

  // TODO(tcp): other tests:
  //  - sends sends SYN with different IP address (current routing logic doesn't
  //  allow us to bind to e.g. a 127.0.0.2 address for the raw socket).
  //  - rebind in connect() (e.g. bound-to-any-addr then connect())

  // bind+connect tests:
  //  - implicit bind (unbound)
  //  - implicit bind (3x: bound to any-addr+port; bound to addr+any-port;
  //    bound to any-addr+any-port)
  //  - explicit bind
  //  - rebind another socket after first socket is connected
}

static void basic_connect_test2(void) {
  KTEST_BEGIN("TCP: basic connect() (v2)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));

  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_EQ(0, vfs_close(s.raw_socket));
}

void tcp_test(void) {
  KTEST_SUITE_BEGIN("TCP");
  const int initial_cache_size = vfs_cache_size();

  tcp_key_test();
  tcp_socket_test();
  sockopt_test();
  bind_test();
  multi_bind_test();
  basic_connect_test();
  basic_connect_test2();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
