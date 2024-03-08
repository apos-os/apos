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

#include "dev/net/tuntap.h"

#include "common/endian.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/socket.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/vfs.h"

#define BUFSIZE 500
#define SRC_IP "127.0.5.1"
#define DST_IP "127.0.5.2"

typedef struct {
  int sock;
  int tt_fd;
} test_fixture_t;

static void basic_tx_test(test_fixture_t* f) {
  KTEST_BEGIN("TUN/TAP: basic TX test (to NIC's IP)");
  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(
      2, net_sendto(f->sock, "de", 2, 0, (struct sockaddr*)&dst, sizeof(dst)));

  // We should get an IP header, a UDP header, and some data.
  char* buf = kmalloc(BUFSIZE);
  kmemset(buf, 0, BUFSIZE);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  const ip4_hdr_t* ip4_hdr = (const ip4_hdr_t*)buf;
  KEXPECT_EQ(ip4_hdr->src_addr, str2inet(SRC_IP));
  KEXPECT_EQ(ip4_hdr->dst_addr, str2inet(DST_IP));
  KEXPECT_EQ(IPPROTO_UDP, ip4_hdr->protocol);

  const udp_hdr_t* udp_hdr = (const udp_hdr_t*)(buf + sizeof(ip4_hdr_t));
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("abc", buf + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));

  // Test the second packet.
  kmemset(buf, 0, BUFSIZE);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 2,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(ip4_hdr->src_addr, str2inet(SRC_IP));
  KEXPECT_EQ(ip4_hdr->dst_addr, str2inet(DST_IP));
  KEXPECT_EQ(IPPROTO_UDP, ip4_hdr->protocol);

  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("de", buf + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));


  KTEST_BEGIN("TUN/TAP: bufsize is enforced (drops extra packets)");
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  // These two should silently fail (drop the packet).
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));

  // On the other end, should only get two packets.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));

  // ...but now should be able to transmit again.
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));

  kfree(buf);
}

void tuntap_test(void) {
  KTEST_SUITE_BEGIN("TUN/TAP tests");

  KTEST_BEGIN("TUN/TAP: test setup");
  test_fixture_t fixture;
  apos_dev_t id;
  nic_t* nic = tuntap_create(BUFSIZE, 0, &id);
  KEXPECT_NE(NULL, nic);

  kspin_lock(&nic->lock);
  nic->addrs[0].addr.family = ADDR_INET;
  nic->addrs[0].addr.a.ip4.s_addr = str2inet(SRC_IP);
  nic->addrs[0].prefix_len = 24;
  kspin_unlock(&nic->lock);

  KEXPECT_EQ(0, vfs_mknod("_tuntap_test_dev", VFS_S_IFCHR | VFS_S_IRWXU, id));
  fixture.tt_fd = vfs_open("_tuntap_test_dev", VFS_O_RDWR);
  KEXPECT_GE(fixture.tt_fd, 0);

  fixture.sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(fixture.sock, 0);

  struct sockaddr_in src = str2sin("0.0.0.0", 1234);
  KEXPECT_EQ(0, net_bind(fixture.sock, (struct sockaddr*)&src, sizeof(src)));

  basic_tx_test(&fixture);

  KTEST_BEGIN("TUN/TAP: test teardown");
  // Send some more packets to make sure we delete queued packets.
  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(3, net_sendto(fixture.sock, "abc", 3, 0, (struct sockaddr*)&dst,
                           sizeof(dst)));
  KEXPECT_EQ(3, net_sendto(fixture.sock, "def", 3, 0, (struct sockaddr*)&dst,
                           sizeof(dst)));

  KEXPECT_EQ(0, vfs_close(fixture.sock));
  KEXPECT_EQ(0, vfs_close(fixture.tt_fd));
  KEXPECT_EQ(0, vfs_unlink("_tuntap_test_dev"));
  KEXPECT_EQ(0, tuntap_destroy(id));
}
