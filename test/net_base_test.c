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
#include "test/test_nic.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TAP_BUFSIZE 500
#define SRC_IP "127.0.5.1"
#define SRC_IP2 "127.0.5.8"
#define SRC_IP3 "127.0.5.130"
#define DST_IP "127.0.5.15"

typedef struct {
  test_ttap_t nic;
  test_ttap_t nic2;
  test_ttap_t nic3;
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
  nbr_cache_clear(t->nic.n);
  kspin_lock(&t->nic.n->lock);
  arp_send_request(t->nic.n, str2inet("127.0.5.8"));
  kspin_unlock(&t->nic.n->lock);
  char mac1[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  char buf[100];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->nic.fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac1));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(eth_hdr->mac_dst, mac1));

  const arp_packet_t* pkt =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(pkt->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(pkt->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, pkt->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), pkt->plen);
  KEXPECT_EQ(1 /* ARP_OPER_REQUEST */, btoh16(pkt->oper));

  KEXPECT_STREQ(t->nic.mac, mac2str(pkt->sha, mac1));
  in_addr_t addr;
  kmemcpy(&addr, pkt->spa, 4);
  KEXPECT_STREQ(SRC_IP, inet2str(addr, addrbuf));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(pkt->tha, mac1));
  kmemcpy(&addr, pkt->tpa, 4);
  KEXPECT_STREQ("127.0.5.8", inet2str(addr, addrbuf));
}

static void arp_response_test(test_fixture_t* t) {
  KTEST_BEGIN("ARP: get response");
  nbr_cache_clear(t->nic.n);
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
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  char buf[100];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->nic.fd, buf, 100));

  arp_rx(t->nic.n, pbuf);

  KEXPECT_EQ(0, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  char mac1[NIC_MAC_PRETTY_LEN];
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(entry.mac.addr, mac1));
}

static void arp_recv_request_test(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (first NIC IP)");
  nbr_cache_clear(t->nic.n);
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
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  arp_rx(t->nic.n, pbuf);

  // Should get a reply with this NIC's MAC address.
  char mac[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->nic.fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(eth_hdr->mac_dst, mac));

  const arp_packet_t* reply =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(reply->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(reply->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, reply->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), reply->plen);
  KEXPECT_EQ(2 /* ARP_OPER_REPLY */, btoh16(reply->oper));

  KEXPECT_STREQ(t->nic.mac, mac2str(reply->sha, mac));
  kmemcpy(&addr, reply->spa, 4);
  KEXPECT_STREQ(SRC_IP, inet2str(addr, addrbuf));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(reply->tha, mac));
  kmemcpy(&addr, reply->tpa, 4);
  KEXPECT_STREQ("5.6.7.8", inet2str(addr, addrbuf));
}

static void arp_recv_request_test2(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (second NIC IP)");
  nbr_cache_clear(t->nic.n);
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
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  arp_rx(t->nic.n, pbuf);

  // Should get a reply with this NIC's MAC address.
  char mac[NIC_MAC_PRETTY_LEN];
  char addrbuf[INET_PRETTY_LEN];
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(arp_packet_t),
             vfs_read(t->nic.fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(eth_hdr->mac_dst, mac));

  const arp_packet_t* reply =
      (const arp_packet_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(1 /* ARP_HTYPE_ETH */, btoh16(reply->htype));
  KEXPECT_EQ(0x0800 /* ET_IPV4 */, btoh16(reply->ptype));
  KEXPECT_EQ(ETH_MAC_LEN, reply->hlen);
  KEXPECT_EQ(sizeof(in_addr_t), reply->plen);
  KEXPECT_EQ(2 /* ARP_OPER_REPLY */, btoh16(reply->oper));

  KEXPECT_STREQ(t->nic.mac, mac2str(reply->sha, mac));
  kmemcpy(&addr, reply->spa, 4);
  KEXPECT_STREQ(SRC_IP2, inet2str(addr, addrbuf));
  KEXPECT_STREQ("07:08:09:0A:0B:0C", mac2str(reply->tha, mac));
  kmemcpy(&addr, reply->tpa, 4);
  KEXPECT_STREQ("5.6.7.8", inet2str(addr, addrbuf));
}

static void arp_recv_request_test3(test_fixture_t* t) {
  KTEST_BEGIN("ARP: receive request (not our IP)");
  nbr_cache_clear(t->nic.n);
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
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  arp_rx(t->nic.n, pbuf);

  // Should be ignored --- no reply.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
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

  // Try with an address on a later NIC after we would have matched a normal
  // route.
  kmemset(&dst, 0x12, sizeof(dst));
  dst.family = AF_INET;
  dst.a.ip4.s_addr = str2inet(SRC_IP3);
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ("lo0", result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_EQ(result.src.a.ip4.s_addr, str2inet(SRC_IP3));
  nic_put(result.nic);


  KTEST_BEGIN("ip_route(): route to loopback (IPv6)");
  char addr[INET6_PRETTY_LEN];
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &dst.a.ip6));

  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ("lo0", result.nic->name);
  KEXPECT_EQ(AF_INET6, result.src.family);
  KEXPECT_STREQ("2001:db8::2", inet62str(&result.src.a.ip6, addr));
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
  KEXPECT_STREQ(t->nic.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // This one should match the second address of the first NIC.
  dst.a.ip4.s_addr = str2inet("127.0.5.9");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP2, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // This one should match the third NIC.
  dst.a.ip4.s_addr = str2inet("127.0.5.131");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic2.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP3, inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);

  // Should match second address of second NIC.
  dst.a.ip4.s_addr = str2inet("127.0.6.1");
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic2.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ("127.0.5.4", inet2str(result.src.a.ip4.s_addr, addr));
  nic_put(result.nic);
}

static void route_longest_prefix_v6_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): route to longest prefix (IPv6)");
  netaddr_t dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::5", &dst.a.ip6));

  char addr[INET6_PRETTY_LEN];
  ip_routed_t result;
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic3.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET6, result.src.family);
  KEXPECT_STREQ("2001:db8::2", inet62str(&result.src.a.ip6, addr));
  nic_put(result.nic);

  // This one should match the first NIC, not the third.
  KEXPECT_EQ(0, str2inet6("2001:db8::1:0:5", &dst.a.ip6));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET6, result.src.family);
  KEXPECT_STREQ("2001:db8::1", inet62str(&result.src.a.ip6, addr));
  nic_put(result.nic);

  // This one should match the second addr of the third NIC.
  KEXPECT_EQ(0, str2inet6("2001:db8:1::5", &dst.a.ip6));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_TRUE(netaddr_eq(&dst, &result.nexthop));
  KEXPECT_STREQ(t->nic3.n->name, result.nic->name);
  KEXPECT_EQ(AF_INET6, result.src.family);
  KEXPECT_STREQ("2001:db8:1::2", inet62str(&result.src.a.ip6, addr));
  nic_put(result.nic);
}

static void route_default_route_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): no default route");
  netaddr_t orig_default_nexthop;
  char orig_default_nic[NIC_MAX_NAME_LEN];
  ip_get_default_route(ADDR_INET, &orig_default_nexthop, orig_default_nic);

  netaddr_t nexthop;
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(ADDR_INET, nexthop, "");

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
  ip_set_default_route(ADDR_INET, nexthop, t->nic.n->name);
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route with bad NIC name");
  nexthop.family = AF_INET;
  nexthop.a.ip4.s_addr = str2inet("1.2.3.4");
  ip_set_default_route(ADDR_INET, nexthop, "not_a_nic");
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route set");
  nexthop.family = AF_INET;
  nexthop.a.ip4.s_addr = str2inet("1.2.3.4");
  ip_set_default_route(ADDR_INET, nexthop, t->nic.n->name);
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_EQ(t->nic.n, result.nic);
  KEXPECT_EQ(AF_INET, result.src.family);
  KEXPECT_STREQ(SRC_IP, inet2str(result.src.a.ip4.s_addr, addr));
  KEXPECT_EQ(AF_INET, result.nexthop.family);
  KEXPECT_STREQ("1.2.3.4", inet2str(result.nexthop.a.ip4.s_addr, addr));
  nic_put(result.nic);


  KTEST_BEGIN("ip_route(): default route set (no usable addrs on NIC)");
  nexthop.family = AF_INET;
  nexthop.a.ip4.s_addr = str2inet("1.2.3.4");
  ip_set_default_route(ADDR_INET, nexthop, t->nic3.n->name);
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_FALSE(ip_route(dst, &result));

  ip_set_default_route(ADDR_INET, orig_default_nexthop, orig_default_nic);
}

static void route_default_route_v6_test(test_fixture_t* t) {
  KTEST_BEGIN("ip_route(): no default route (IPv6)");
  netaddr_t orig_default_nexthop;
  char orig_default_nic[NIC_MAX_NAME_LEN];
  ip_get_default_route(ADDR_INET6, &orig_default_nexthop, orig_default_nic);

  netaddr_t nexthop;
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(ADDR_INET6, nexthop, "");

  netaddr_t dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2607:f8b0:4006:821::2004", &dst.a.ip6));

  char addr[INET6_PRETTY_LEN];
  ip_routed_t result;
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): no default route (with NIC name) (IPv6)");
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(ADDR_INET6, nexthop, t->nic.n->name);
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route with bad NIC name (IPv6)");
  nexthop.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::100", &nexthop.a.ip6));
  ip_set_default_route(ADDR_INET6, nexthop, "not_a_nic");
  KEXPECT_FALSE(ip_route(dst, &result));


  KTEST_BEGIN("ip_route(): default route set (IPv6)");
  nexthop.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::100", &nexthop.a.ip6));
  ip_set_default_route(ADDR_INET6, nexthop, t->nic.n->name);
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_TRUE(ip_route(dst, &result));
  KEXPECT_EQ(t->nic.n, result.nic);
  KEXPECT_EQ(AF_INET6, result.src.family);
  KEXPECT_STREQ("2001:db8::1", inet62str(&result.src.a.ip6, addr));
  KEXPECT_EQ(AF_INET6, result.nexthop.family);
  KEXPECT_STREQ("2001:db8::100", inet62str(&result.nexthop.a.ip6, addr));
  nic_put(result.nic);


  KTEST_BEGIN("ip_route(): default route set (no usable addrs on NIC) (IPv6)");
  nexthop.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::100", &nexthop.a.ip6));
  ip_set_default_route(ADDR_INET6, nexthop, t->nic2.n->name);
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_FALSE(ip_route(dst, &result));

  ip_set_default_route(ADDR_INET6, orig_default_nexthop, orig_default_nic);
}

static void ip_route_tests(test_fixture_t* t) {
  route_to_loopback_test(t);
  route_longest_prefix_test(t);
  route_longest_prefix_v6_test(t);
  route_default_route_test(t);
  route_default_route_v6_test(t);
}

static void addr_cmp_tests(void) {
  KTEST_BEGIN("sockaddr_equal() (IPv4)");
  struct sockaddr_storage a, b;
  kmemset(&a, 0, sizeof(a));
  kmemset(&b, 0, sizeof(b));
  a.sa_family = AF_INET;
  b.sa_family = AF_INET6;
  KEXPECT_FALSE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));

  struct sockaddr_in* a_v4 = (struct sockaddr_in*)&a;
  struct sockaddr_in* b_v4 = (struct sockaddr_in*)&b;
  kmemset(&a, 0, sizeof(a));
  kmemset(&b, 0xff, sizeof(b));
  a_v4->sin_family = AF_INET;
  b_v4->sin_family = AF_INET;
  a_v4->sin_addr.s_addr = 0xabcd;
  b_v4->sin_addr.s_addr = 0xabcd;
  a_v4->sin_port = 1234;
  b_v4->sin_port = 1234;
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v4->sin_addr.s_addr = 0xabce;
  KEXPECT_FALSE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v4->sin_addr.s_addr = 0xabcd;
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v4->sin_port = 5678;
  KEXPECT_FALSE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v4->sin_port = 1234;
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));


  KTEST_BEGIN("sockaddr_equal() (IPv6)");
  struct sockaddr_in6* a_v6 = (struct sockaddr_in6*)&a;
  struct sockaddr_in6* b_v6 = (struct sockaddr_in6*)&b;
  kmemset(&a, 0, sizeof(a));
  kmemset(&b, 0xff, sizeof(b));
  a_v6->sin6_family = AF_INET6;
  b_v6->sin6_family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &a_v6->sin6_addr));
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &b_v6->sin6_addr));
  a_v6->sin6_port = 1234;
  b_v6->sin6_port = 1234;
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &a_v6->sin6_addr));
  KEXPECT_FALSE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &a_v6->sin6_addr));
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v6->sin6_port = 5678;
  KEXPECT_FALSE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
  a_v6->sin6_port = 1234;
  KEXPECT_TRUE(sockaddr_equal((struct sockaddr*)&a, (struct sockaddr*)&b));
}

// TODO(aoates): neighbor cache tests:
//  - time out
//  - multiple pending requests

void net_base_test(void) {
  KTEST_SUITE_BEGIN("Network base code");
  KTEST_BEGIN("Network base: test setup");
  test_fixture_t fixture;
  KEXPECT_EQ(0, test_ttap_create(&fixture.nic, TUNTAP_TAP_MODE));

  nic_t* nic = fixture.nic.n;
  kspin_lock(&nic->lock);
  nic_add_addr_v6(nic, "2001:db8::1", 64, NIC_ADDR_ENABLED);
  nic_add_addr(nic, SRC_IP, 24, NIC_ADDR_ENABLED);
  nic_add_addr(nic, SRC_IP2, 31, NIC_ADDR_ENABLED);
  kspin_unlock(&nic->lock);

  KEXPECT_EQ(0, test_ttap_create(&fixture.nic2, TUNTAP_TAP_MODE));
  kspin_lock(&fixture.nic2.n->lock);
  nic_add_addr(fixture.nic2.n, SRC_IP3, 30, NIC_ADDR_ENABLED);
  nic_add_addr(fixture.nic2.n, "127.0.5.4", 16, NIC_ADDR_ENABLED);
  kspin_unlock(&fixture.nic2.n->lock);

  // A third ipv6-only NIC.
  KEXPECT_EQ(0, test_ttap_create(&fixture.nic3, TUNTAP_TAP_MODE));

  kspin_lock(&fixture.nic3.n->lock);
  nic_add_addr_v6(fixture.nic3.n, "2001:db8::2", 96, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic3.n, "2001:db8:1::2", 70, NIC_ADDR_ENABLED);
  kspin_unlock(&fixture.nic3.n->lock);

  // Run the tests.
  str_tests();
  arp_tests(&fixture);
  ip_route_tests(&fixture);
  addr_cmp_tests();

  KTEST_BEGIN("Network base: test teardown");
  test_ttap_destroy(&fixture.nic);
  test_ttap_destroy(&fixture.nic2);
  test_ttap_destroy(&fixture.nic3);
}
