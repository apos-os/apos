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

#include "arch/common/endian.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "net/eth/arp/arp.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

void eth_rx(nic_t* nic, pbuf_t* pb) {
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

  pbuf_pop_header(pb, sizeof(eth_hdr_t));
  switch (hdr.ethertype) {
    case ET_ARP:
      arp_rx(nic, pb);
      return;

    default:
      KLOG(INFO, "rx(%s): dropping packet with unknown ethertype %#06x\n",
           nic->name, hdr.ethertype);
      pbuf_free(pb);
      return;
  }
}

void eth_add_hdr(pbuf_t* pb, const uint8_t mac_dst[], const uint8_t mac_src[],
                 ethertype_vals_t ethertype) {
  pbuf_push_header(pb, sizeof(eth_hdr_t));
  eth_hdr_t* hdr = (eth_hdr_t*)pbuf_get(pb);
  kmemcpy(hdr->mac_dst, mac_dst, ETH_MAC_LEN);
  kmemcpy(hdr->mac_src, mac_src, ETH_MAC_LEN);
  hdr->ethertype = htob16(ethertype);
}
