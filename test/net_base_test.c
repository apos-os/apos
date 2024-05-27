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
#include "common/endian.h"
#include "dev/net/nic.h"
#include "dev/net/tuntap.h"
#include "net/addr.h"
#include "net/eth/arp/arp.h"
#include "net/eth/arp/arp_packet.h"
#include "net/eth/eth.h"
#include "net/ip/route.h"
#include "net/mac.h"
#include "net/neighbor_cache.h"
#include "net/neighbor_cache_ops.h"
#include "net/pbuf.h"
#include "net/util.h"
#include "proc/notification.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TAP_BUFSIZE 500
#define SRC_IP "127.0.5.1"
#define SRC_IP2 "127.0.5.8"
#define SRC_IP3 "127.0.5.130"
#define DST_IP "127.0.5.15"

typedef struct {
  int tap_fd;
  nic_t* nic;
  nic_t* nic2;
} test_fixture_t;

static void str_tests(void) {
  char buf[100];

  KTEST_BEGIN("inet2str()");
  KEXPECT_EQ(&buf[0], inet2str(0xffffffff, buf));
  KEXPECT_STREQ("255.255.255.255", buf);
  KEXPECT_EQ(&buf[0], inet2str(0, buf));
  KEXPECT_STREQ("0.0.0.0", buf);
  KEXPECT_EQ(&buf[0], inet2str(htob32(0x01020304), buf));
  KEXPECT_STREQ("1.2.3.4", buf);


  KTEST_BEGIN("str2inet()");
  KEXPECT_EQ(0, str2inet("abc"));
  KEXPECT_EQ(0, str2inet("1.2.3.4."));
  KEXPECT_EQ(0, str2inet("1.2.3."));
  KEXPECT_EQ(0, str2inet("1.a.3.4"));
  KEXPECT_EQ(htob32(0x01020304), str2inet("1.2.3.4"));
  KEXPECT_EQ(htob32(0xffffffff), str2inet("255.255.255.255"));
  KEXPECT_EQ(htob32(0x1), str2inet("0.0.0.1"));
  KEXPECT_EQ(0, str2inet("0.0.256.1"));


  KTEST_BEGIN("mac2str()");
  KEXPECT_STREQ("00:00:00:00:00:00",
                mac2str((uint8_t[]){0, 0, 0, 0, 0, 0}, buf));
  KEXPECT_STREQ("00:01:FF:00:AB:00",
                mac2str((uint8_t[]){0, 1, 0xff, 0, 0xab, 0}, buf));


  KTEST_BEGIN("str2mac()");
  uint8_t mac[6];
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:00", mac));
  KEXPECT_STREQ("00:00:00:00:00:00", mac2str(mac, buf));
  KEXPECT_EQ(0, str2mac("00:0f:00:aB:00:ff", mac));
  KEXPECT_STREQ("00:0F:00:AB:00:FF", mac2str(mac, buf));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:00:aB:00:ff1", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:00:aB:00:f", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:00:aB:00:ff:11", mac));
  KEXPECT_EQ(-EINVAL, str2mac("x0:0f:00:aB:00:ff:11", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:0x:aB:00:ff", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:x0:aB:00:ff", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f:00:aB:00:f:", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00:0f.00:aB:00:ff", mac));
  KEXPECT_EQ(-EINVAL, str2mac("00!0f:00:aB:00:ff", mac));
}

static void arp_request_test(test_fixture_t* t) {
  KTEST_BEGIN("ARP: send request");
  nbr_cache_clear(t->nic);
  kspin_lock(&t->nic->lock);
  arp_send_request(t->nic, str2inet("127.0.5.8"));
  kspin_unlock(&t->nic->lock);
  char mac1[NIC_MAC_PRETTY_LEN], mac2[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  char buf[100];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->tap_fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(eth_hdr->mac_src, mac2));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(eth_hdr->mac_dst, mac2));

  const arp_packet_t* pkt =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(pkt->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(pkt->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, pkt->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), pkt->plen);
  KEXPECT_EQ(1 /* ARP_OPER_REQUEST */, btoh16(pkt->oper));

  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(pkt->sha, mac2));
  in_addr_t addr;
  kmemcpy(&addr, pkt->spa, 4);
  KEXPECT_STREQ(SRC_IP, inet2str(addr, addrbuf));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(pkt->tha, mac2));
  kmemcpy(&addr, pkt->tpa, 4);
  KEXPECT_STREQ("127.0.5.8", inet2str(addr, addrbuf));
}

static void arp_response_test(test_fixture_t* t) {
  KTEST_BEGIN("ARP: get response");
  nbr_cache_clear(t->nic);
  pbuf_t* pbuf = pbuf_create(0, sizeof(arp_packet_t));
  arp_packet_t* pkt = (arp_packet_t*)pbuf_get(pbuf);
  pkt->htype = btoh16(1);
  pkt->ptype = btoh16(0x0800);
  pkt->hlen = ETH_MAC_LEN;
  pkt->plen = sizeof(in_addr_t);
  pkt->oper = htob16(ARP_OPER_REPLY);

  KEXPECT_EQ(0, str2mac("07:08:09:0a:0b:0c", pkt->sha));
  in_addr_t addr = str2inet("5.6.7.8");
  kmemcpy(pkt->spa, &addr, 4);

  KEXPECT_EQ(0, str2mac("01:02:03:04:05:06", pkt->tha));
  addr = str2inet("1.2.3.4");
  kmemcpy(pkt->tpa, &addr, 4);

  netaddr_t na;
  na.family = AF_INET;
  na.a.ip4.s_addr = str2inet("5.6.7.8");
  nbr_cache_entry_t entry;
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic, na, &entry, 0));
  char buf[100];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->tap_fd, buf, 100));

  arp_rx(t->nic, pbuf);

  KEXPECT_EQ(0, nbr_cache_lookup(t->nic, na, &entry, 0));
  char mac1[NIC_MAC_PRETTY_LEN];
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(entry.mac.addr, mac1));
}

static void arp_recv_request_test(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (first NIC IP)");
  nbr_cache_clear(t->nic);
  pbuf_t* pbuf = pbuf_create(0, sizeof(arp_packet_t));
  arp_packet_t* pkt = (arp_packet_t*)pbuf_get(pbuf);
  pkt->htype = btoh16(1);
  pkt->ptype = btoh16(0x0800);
  pkt->hlen = ETH_MAC_LEN;
  pkt->plen = sizeof(in_addr_t);
  pkt->oper = htob16(ARP_OPER_REQUEST);

  KEXPECT_EQ(0, str2mac("07:08:09:0a:0b:0c", pkt->sha));
  in_addr_t addr = str2inet("5.6.7.8");
  kmemcpy(pkt->spa, &addr, 4);

  // This _should_ be the any-address, but test a different one.
  KEXPECT_EQ(0, str2mac("01:02:03:04:05:06", pkt->tha));
  addr = str2inet(SRC_IP);
  kmemcpy(pkt->tpa, &addr, 4);

  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  arp_rx(t->nic, pbuf);

  // Should get a reply with this NIC's MAC address.
  char mac1[NIC_MAC_PRETTY_LEN], mac2[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->tap_fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(eth_hdr->mac_src, mac2));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(eth_hdr->mac_dst, mac2));

  const arp_packet_t* reply =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(reply->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(reply->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, reply->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), reply->plen);
  KEXPECT_EQ(2 /* ARP_OPER_REPLY */, btoh16(reply->oper));

  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(reply->sha, mac2));
  kmemcpy(&addr, reply->spa, 4);
  KEXPECT_STREQ(SRC_IP, inet2str(addr, addrbuf));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(reply->tha, mac2));
  kmemcpy(&addr, reply->tpa, 4);
  KEXPECT_STREQ("5.6.7.8", inet2str(addr, addrbuf));
}

static void arp_recv_request_test2(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (second NIC IP)");
  nbr_cache_clear(t->nic);
  pbuf_t* pbuf = pbuf_create(0, sizeof(arp_packet_t));
  arp_packet_t* pkt = (arp_packet_t*)pbuf_get(pbuf);
  pkt->htype = btoh16(1);
  pkt->ptype = btoh16(0x0800);
  pkt->hlen = ETH_MAC_LEN;
  pkt->plen = sizeof(in_addr_t);
  pkt->oper = htob16(ARP_OPER_REQUEST);

  KEXPECT_EQ(0, str2mac("07:08:09:0a:0b:0c", pkt->sha));
  in_addr_t addr = str2inet("5.6.7.8");
  kmemcpy(pkt->spa, &addr, 4);

  // This _should_ be the any-address, but test a different one.
  KEXPECT_EQ(0, str2mac("01:02:03:04:05:06", pkt->tha));
  addr = str2inet(SRC_IP2);
  kmemcpy(pkt->tpa, &addr, 4);

  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  arp_rx(t->nic, pbuf);

  // Should get a reply with this NIC's MAC address.
  char mac1[NIC_MAC_PRETTY_LEN], mac2[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->tap_fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(eth_hdr->mac_src, mac2));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(eth_hdr->mac_dst, mac2));

  const arp_packet_t* reply =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(reply->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(reply->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, reply->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), reply->plen);
  KEXPECT_EQ(2 /* ARP_OPER_REPLY */, btoh16(reply->oper));

  KEXPECT_STREQ(mac2str(t->nic->mac.addr, mac1),
                mac2str(reply->sha, mac2));
  kmemcpy(&addr, reply->spa, 4);
  KEXPECT_STREQ(SRC_IP2, inet2str(addr, addrbuf));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(reply->tha, mac2));
  kmemcpy(&addr, reply->tpa, 4);
  KEXPECT_STREQ("5.6.7.8", inet2str(addr, addrbuf));
}

static void arp_recv_request_test3(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (not our IP)");
  nbr_cache_clear(t->nic);
  pbuf_t* pbuf = pbuf_create(0, sizeof(arp_packet_t));
  arp_packet_t* pkt = (arp_packet_t*)pbuf_get(pbuf);
  pkt->htype = btoh16(1);
  pkt->ptype = btoh16(0x0800);
  pkt->hlen = ETH_MAC_LEN;
  pkt->plen = sizeof(in_addr_t);
  pkt->oper = htob16(ARP_OPER_REQUEST);

  KEXPECT_EQ(0, str2mac("07:08:09:0a:0b:0c", pkt->sha));
  in_addr_t addr = str2inet("5.6.7.8");
  kmemcpy(pkt->spa, &addr, 4);

  // This _should_ be the any-address, but test a different one.
  KEXPECT_EQ(0, str2mac("01:02:03:04:05:06", pkt->tha));
  addr = str2inet(DST_IP);
  kmemcpy(pkt->tpa, &addr, 4);

  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  arp_rx(t->nic, pbuf);

  // Should be ignored --- no reply.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void arp_tests(test_fixture_t* t) {
  arp_request_test(t);
  arp_response_test(t);
  arp_recv_request_test(t);
  arp_recv_request_test2(t);
  arp_recv_request_test3(t);
}

static void route_to_loopback_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): route to loopback");
  netaddr_t dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET;
  dst.a.ip4.s_addr = str2inet(SRC_IP);

  ip_routed_t result;
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ("lo0", result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_EQ(result.src.a.ip4.s_addr, str2inet(SRC_IP));
  nic_put(result.nic);

  // Do it again with a different bit pattern filling the address.
  kmemset(&dst, 0x12, sizeof(dst));
  dst.family = AF_INET;
  dst.a.ip4.s_addr = str2inet(SRC_IP);
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ("lo0", result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_EQ(result.src.a.ip4.s_addr, str2inet(SRC_IP));
  nic_put(result.nic);
}

static void route_longest_prefix_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): route to longest prefix");
  netaddr_t dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET;
  dst.a.ip4.s_addr = str2inet("127.0.5.5");

  char addr[INET_PRETTY_LEN];
  ip_routed_t result;
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // This one should match the second address of the first NIC.
  dst.a.ip4.s_addr = str2inet("127.0.5.9");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP2, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // This one should match the third NIC.
  dst.a.ip4.s_addr = str2inet("127.0.5.131");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic2->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP3, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // Should match second address of second NIC.
  dst.a.ip4.s_addr = str2inet("127.0.6.1");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic2->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ("127.0.5.4", inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);
}

static void route_default_route_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): no default route");
  netaddr_t orig_default_nexthop;
  char orig_default_nic[NIC_MAX_NAME_LEN];
  ip_get_default_route(&orig_default_nexthop, orig_default_nic);

  netaddr_t nexthop;
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(nexthop, "");

  netaddr_t dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET;
  dst.a.ip4.s_addr = str2inet("8.8.8.8");

  char addr[INET_PRETTY_LEN];
  ip_routed_t result;
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): no default route (with NIC name)");
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(nexthop, t->nic->name);
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route with bad NIC name");
  nexthop.family = AF_INET;
  nexthop.a.ip4.s_addr = str2inet("1.2.3.4");
  ip_set_default_route(nexthop, "not_a_nic");
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route set");
  nexthop.family = AF_INET;
  nexthop.a.ip4.s_addr = str2inet("1.2.3.4");
  ip_set_default_route(nexthop, t->nic->name);
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_EQ(t->nic, result.nic);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP, inet2str(result.src.a.ip4.s_addr, addr));
  KEXPECT_EQ(AF_INET, result.nexthop.family);
  KEXPECT_STREQ("1.2.3.4", inet2str(result.nexthop.a.ip4.s_addr, addr));
  nic_put(result.nic);

  ip_set_default_route(orig_default_nexthop, orig_default_nic);
}

static void ip_route_tests(test_fixture_t* t) {
  route_to_loopback_test(t);
  route_longest_prefix_test(t);
  route_default_route_test(t);
}

// TODO(aoates): neighbor cache tests:
//  - time out
//  - multiple pending requests

void net_base_test(void) {
  KTEST_SUITE_BEGIN("Network base code");
  KTEST_BEGIN("Network base: test setup");
  test_fixture_t fixture;
  apos_dev_t id, id2;
  nic_t* nic = tuntap_create(TAP_BUFSIZE, TUNTAP_TAP_MODE, &id);
  KEXPECT_NE(NULL, nic);
  fixture.nic = nic;

  kspin_lock(&nic->lock);
  nic->addrs[0].a.addr.family = ADDR_INET;
  nic->addrs[0].a.addr.a.ip4.s_addr = str2inet(SRC_IP);
  nic->addrs[0].a.prefix_len = 24;
  nic->addrs[0].state = NIC_ADDR_ENABLED;
  nic->addrs[1].a.addr.family = ADDR_INET;
  nic->addrs[1].a.addr.a.ip4.s_addr = str2inet(SRC_IP2);
  nic->addrs[1].a.prefix_len = 31;
  nic->addrs[1].state = NIC_ADDR_ENABLED;
  kspin_unlock(&nic->lock);

  fixture.nic2 = tuntap_create(TAP_BUFSIZE, TUNTAP_TAP_MODE, &id2);
  KEXPECT_NE(NULL, fixture.nic2);

  kspin_lock(&fixture.nic2->lock);
  fixture.nic2->addrs[0].a.addr.family = ADDR_INET;
  fixture.nic2->addrs[0].a.addr.a.ip4.s_addr = str2inet(SRC_IP3);
  fixture.nic2->addrs[0].a.prefix_len = 30;
  fixture.nic2->addrs[0].state = NIC_ADDR_ENABLED;
  fixture.nic2->addrs[1].a.addr.family = ADDR_INET;
  fixture.nic2->addrs[1].a.addr.a.ip4.s_addr = str2inet("127.0.5.4");
  fixture.nic2->addrs[1].a.prefix_len = 16;
  fixture.nic2->addrs[1].state = NIC_ADDR_ENABLED;
  kspin_unlock(&fixture.nic2->lock);

  KEXPECT_EQ(0, vfs_mknod("_tap_test_dev", VFS_S_IFCHR | VFS_S_IRWXU, id));
  fixture.tap_fd = vfs_open("_tap_test_dev", VFS_O_RDWR);
  KEXPECT_GE(fixture.tap_fd, 0);
  vfs_make_nonblock(fixture.tap_fd);

  // Run the tests.
  str_tests();
  arp_tests(&fixture);
  ip_route_tests(&fixture);

  KTEST_BEGIN("Network base: test teardown");
  KEXPECT_EQ(0, vfs_close(fixture.tap_fd));
  KEXPECT_EQ(0, vfs_unlink("_tap_test_dev"));
  KEXPECT_EQ(0, tuntap_destroy(id));
  KEXPECT_EQ(0, tuntap_destroy(id2));
}
