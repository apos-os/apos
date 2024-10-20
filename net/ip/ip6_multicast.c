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
#include "net/ip/ip6_multicast.h"

#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/refcount.h"
#include "dev/net/nic.h"
#include "memory/kmalloc.h"
#include "net/eth/eth.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/multicast.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/ip6_hdr.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

typedef struct {
  struct in6_addr addr;
  refcount_t ref;
} ipv6_mc_sub_t;

static void make_nic_mc(const struct in6_addr* addr, nic_mac_t* mac_out) {
  mac_out->addr[0] = 0x33;
  mac_out->addr[1] = 0x33;
  mac_out->addr[2] = addr->s6_addr[12];
  mac_out->addr[3] = addr->s6_addr[13];
  mac_out->addr[4] = addr->s6_addr[14];
  mac_out->addr[5] = addr->s6_addr[15];
}

static uint32_t hash(const struct in6_addr* addr) {
  return fnv_hash_array(addr, sizeof(struct in6_addr));
}

static void build_mld(void* arg, htbl_key_t key, void* val) {
  ipv6_mc_sub_t* sub = (ipv6_mc_sub_t*)val;
  mld_multicast_record_t** record_ptr = (mld_multicast_record_t**)arg;
  mld_multicast_record_t* record = *record_ptr;
  record->record_type = MLD_MODE_IS_EXCLUDE;
  record->aux_data_len = 0;
  record->num_sources = 0;
  kmemcpy(&record->multicast_addr, &sub->addr, sizeof(struct in6_addr));
  (*record_ptr)++;
}

static int send_mld_listener_report(nic_t* nic) {
  kspin_lock(&nic->lock);
  int addrs = htbl_size(&nic->ipv6.multicast);
  if (addrs == 0) {
    kspin_unlock(&nic->lock);
    KLOG(DEBUG2, "IPv6: ignoring MLD query, no multicast groups\n");
    return 0;
  }

  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE + sizeof(mld_listener_report_t),
                           sizeof(mld_multicast_record_t) * addrs);
  mld_multicast_record_t* records = (mld_multicast_record_t*)pbuf_get(pb);
  htbl_iterate(&nic->ipv6.multicast, &build_mld, &records);
  KASSERT_DBG((void*)records ==
              pbuf_get(pb) + addrs * sizeof(mld_multicast_record_t));

  struct in6_addr src_ip;
  kmemset(&src_ip, 0, sizeof(src_ip));
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state == NIC_ADDR_ENABLED &&
        nic->addrs[i].a.addr.family == AF_INET6 &&
        ip6_is_link_local(&nic->addrs[i].a.addr.a.ip6)) {
      kmemcpy(&src_ip, &nic->addrs[i].a.addr.a.ip6, sizeof(struct in6_addr));
      break;
    }
  }
  kspin_unlock(&nic->lock);

  pbuf_push_header(pb, sizeof(mld_listener_report_t));
  mld_listener_report_t* report = (mld_listener_report_t*)pbuf_get(pb);
  report->hdr.type = ICMPV6_MLD_LISTENER_REPORT;
  report->hdr.code = 0;
  report->hdr.checksum = 0;
  report->reserved = 0;
  report->num_mc_records = htob16(addrs);

  ip6_pseudo_hdr_t ip6_phdr;
  ip6_phdr.src_addr = src_ip;
  KASSERT(0 == str2inet6("ff02::16", &ip6_phdr.dst_addr));
  kmemset(&ip6_phdr._zeroes, 0, sizeof(ip6_phdr._zeroes));
  ip6_phdr.next_hdr = IPPROTO_ICMPV6;
  ip6_phdr.payload_len = htob32(pbuf_size(pb));

  report->hdr.checksum =
      ip_checksum2(&ip6_phdr, sizeof(ip6_phdr), pbuf_get(pb), pbuf_size(pb));
  ip6_add_hdr(pb, &ip6_phdr.src_addr, &ip6_phdr.dst_addr, IPPROTO_ICMPV6, 0);

  nic_mac_t eth_dst;
  ip6_multicast_mac(&ip6_phdr.dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
  return eth_send_raw(nic, pb);
}

static int send_mld_listener_report_one_addr(nic_t* nic, int record_type,
                                             const struct in6_addr* addr) {
  kspin_lock(&nic->lock);
  struct in6_addr src_ip;
  kmemset(&src_ip, 0, sizeof(src_ip));
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state == NIC_ADDR_ENABLED &&
        nic->addrs[i].a.addr.family == AF_INET6 &&
        ip6_is_link_local(&nic->addrs[i].a.addr.a.ip6)) {
      kmemcpy(&src_ip, &nic->addrs[i].a.addr.a.ip6, sizeof(struct in6_addr));
      break;
    }
  }
  kspin_unlock(&nic->lock);

  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE + sizeof(mld_listener_report_t),
                           sizeof(mld_multicast_record_t));
  mld_multicast_record_t* record = (mld_multicast_record_t*)pbuf_get(pb);
  record->record_type = record_type;
  record->aux_data_len = 0;
  record->num_sources = 0;
  kmemcpy(&record->multicast_addr, addr, sizeof(struct in6_addr));

  pbuf_push_header(pb, sizeof(mld_listener_report_t));
  mld_listener_report_t* report = (mld_listener_report_t*)pbuf_get(pb);
  report->hdr.type = ICMPV6_MLD_LISTENER_REPORT;
  report->hdr.code = 0;
  report->hdr.checksum = 0;
  report->reserved = 0;
  report->num_mc_records = htob16(1);

  ip6_pseudo_hdr_t ip6_phdr;
  ip6_phdr.src_addr = src_ip;
  KASSERT(0 == str2inet6("ff02::16", &ip6_phdr.dst_addr));
  kmemset(&ip6_phdr._zeroes, 0, sizeof(ip6_phdr._zeroes));
  ip6_phdr.next_hdr = IPPROTO_ICMPV6;
  ip6_phdr.payload_len = htob32(pbuf_size(pb));

  report->hdr.checksum =
      ip_checksum2(&ip6_phdr, sizeof(ip6_phdr), pbuf_get(pb), pbuf_size(pb));
  ip6_add_hdr(pb, &ip6_phdr.src_addr, &ip6_phdr.dst_addr, IPPROTO_ICMPV6, 0);

  nic_mac_t eth_dst;
  ip6_multicast_mac(&ip6_phdr.dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
  return eth_send_raw(nic, pb);
}

int ip6_multicast_join(nic_t* nic, const struct in6_addr* addr) {
  char addr_pretty[INET6_PRETTY_LEN];
  if (addr->s6_addr[0] != 0xff) {
    KLOG(WARNING, "ipv6: cannot join invalid multicast address %s\n",
       inet62str(addr, addr_pretty));
    return -EINVAL;
  }

  KLOG(DEBUG, "ipv6: joining multicast group %s on device %s\n",
       inet62str(addr, addr_pretty), nic->name);
  uint32_t key = hash(addr);
  void* val;
  kspin_lock(&nic->lock);
  if (htbl_get(&nic->ipv6.multicast, key, &val) == 0) {
    ipv6_mc_sub_t* sub = (ipv6_mc_sub_t*)val;
    refcount_inc(&sub->ref);
    kspin_unlock(&nic->lock);
  } else {
    ipv6_mc_sub_t* sub = KMALLOC(ipv6_mc_sub_t);
    kmemcpy(&sub->addr, addr, sizeof(struct in6_addr));
    sub->ref = REFCOUNT_INIT;
    htbl_put(&nic->ipv6.multicast, key, sub);
    kspin_unlock(&nic->lock);

    nic_mac_t mac;
    make_nic_mc(addr, &mac);
    nic->ops->nic_mc_sub(nic, &mac);
    return send_mld_listener_report_one_addr(nic, MLD_CHANGE_TO_EXCLUDE_MODE,
                                             addr);
  }
  return 0;
}

int ip6_multicast_leave(nic_t* nic, const struct in6_addr* addr) {
  char addr_pretty[INET6_PRETTY_LEN];
  if (addr->s6_addr[0] != 0xff) {
    KLOG(WARNING, "ipv6: cannot leave invalid multicast address %s\n",
       inet62str(addr, addr_pretty));
    return -EINVAL;
  }

  KLOG(DEBUG, "ipv6: leaving multicast group %s on device %s\n",
       inet62str(addr, addr_pretty), nic->name);
  uint32_t key = hash(addr);
  void* val;
  kspin_lock(&nic->lock);
  if (htbl_get(&nic->ipv6.multicast, key, &val) == 0) {
    ipv6_mc_sub_t* sub = (ipv6_mc_sub_t*)val;
    bool unsub = false;
    if (refcount_dec(&sub->ref) == 0) {
      KASSERT(htbl_remove(&nic->ipv6.multicast, key) == 0);
      kfree(sub);
      sub = NULL;
      unsub = true;
    }
    kspin_unlock(&nic->lock);

    if (unsub) {
      nic_mac_t mac;
      make_nic_mc(addr, &mac);
      nic->ops->nic_mc_unsub(nic, &mac);
      return send_mld_listener_report_one_addr(nic, MLD_CHANGE_TO_INCLUDE_MODE,
                                               addr);
    }
  } else {
    kspin_unlock(&nic->lock);
    KLOG(DFATAL,
         "ipv6: cannot leave multicast address %s on device %s: not joined\n",
         inet62str(addr, addr_pretty), nic->name);
    return -EINVAL;
  }
  return 0;
}

void ip6_multicast_handle_query(nic_t* nic, const ip6_hdr_t* ip_hdr,
                                pbuf_t* pb) {
  if (!ip6_is_link_local(&ip_hdr->src_addr)) {
    KLOG(INFO, "IPv6: ignoring MLD query from non-link-local address\n");
    pbuf_free(pb);
    return;
  }

  // TODO(ipv6): handle address-specific and source/address-specific queries.
  int result = send_mld_listener_report(nic);
  if (result < 0) {
    KLOG(WARNING, "IPv6: unable to send MLD listener report: %s\n",
         errorname(-result));
  }
  pbuf_free(pb);
}
