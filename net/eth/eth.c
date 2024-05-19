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

#include "net/eth/eth.h"

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "net/link_layer.h"
#include "net/neighbor_cache_ops.h"
#include "net/pbuf.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

// TODO(aoates): this should be configurable.  Per NIC?  Per socket?  How would
// we plumb that?
#define ARP_TIMEOUT_MS 500

#define PRINT_PACKETS 0

void eth_mkbroadcast(uint8_t* mac) {
  kmemset(mac, 0xFF, 6);
}

#if PRINT_PACKETS
static void print_packet(const pbuf_t* pb, const char* type) {
  KLOG(INFO, "##### %s PACKET %d #####", type, get_time_ms());
  const size_t kLineLen = 20;
  for (size_t i = 0; i < pbuf_size(pb); ++i) {
    if (i % kLineLen == 0) {
      KLOG(INFO, "\n%05zx: ", i);
    }
    KLOG(INFO, "%02x ", ((const char*)pbuf_getc(pb))[i]);
  }
  KLOG(INFO, "\n##### END PACKET #####\n");
}
#else
#define print_packet(pb, type)
#endif

int eth_send(nic_t* nic, netaddr_t next_hop, pbuf_t* pb, ethertype_t protocol,
             bool allow_block) {
  if (protocol != ET_IPV4 && protocol != ET_IPV6) {
    KLOG(INFO, "send(%s): dropping packet with unsupported protocol %#06x\n",
         nic->name, protocol);
    return -EINVAL;
  }
  KASSERT((protocol == ET_IPV4 && next_hop.family == ADDR_INET) ||
          (protocol == ET_IPV6 && next_hop.family == ADDR_INET6));
  nbr_cache_entry_t nbr_result;
  int result = nbr_cache_lookup(nic, next_hop, &nbr_result,
                                allow_block ? ARP_TIMEOUT_MS : 0);
  if (result != 0) {
    return result;
  }

  eth_add_hdr(pb, &nbr_result.mac, &nic->mac, protocol);
  return eth_send_raw(nic, pb);
}

int eth_send_raw(nic_t* nic, pbuf_t* pb) {
  print_packet(pb, "TX");
  return nic->ops->nic_tx(nic, pb);
}

void eth_recv(nic_t* nic, pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(eth_hdr_t)) {
    // TODO(aoates): increment a counter
    KLOG(INFO, "recv(%s): dropping too-short packet (%zu bytes)\n", nic->name,
         pbuf_size(pb));
    pbuf_free(pb);
    return;
  }

  eth_hdr_t hdr;
  kmemcpy(&hdr, pbuf_get(pb), sizeof(eth_hdr_t));
  hdr.ethertype = btoh16(hdr.ethertype);
  char buf1[NIC_MAC_PRETTY_LEN], buf2[NIC_MAC_PRETTY_LEN];
  KLOG(DEBUG2, "rx(%s): %s -> %s, ethertype=%#06x\n", nic->name,
       mac2str(hdr.mac_src, buf1), mac2str(hdr.mac_dst, buf2), hdr.ethertype);
  print_packet(pb, "RX");

  pbuf_pop_header(pb, sizeof(eth_hdr_t));
  net_link_recv(nic, pb, hdr.ethertype);
}

void eth_add_hdr(pbuf_t* pb, const nic_mac_t* mac_dst, const nic_mac_t* mac_src,
                 ethertype_t ethertype) {
  pbuf_push_header(pb, sizeof(eth_hdr_t));
  eth_hdr_t* hdr = (eth_hdr_t*)pbuf_get(pb);
  kmemcpy(hdr->mac_dst, &mac_dst->addr, ETH_MAC_LEN);
  kmemcpy(hdr->mac_src, &mac_src->addr, ETH_MAC_LEN);
  hdr->ethertype = htob16(ethertype);
}
