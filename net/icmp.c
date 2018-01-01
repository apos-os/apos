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

#include "net/icmp.h"

#include "arch/common/endian.h"
#include "net/ip/checksum.h"
#include "net/util.h"

pbuf_t* icmp_mkecho(uint16_t id, uint16_t seq) {
  pbuf_t* pb = pbuf_create(INET_HEADER_RESERVE, sizeof(icmp_hdr_t));
  icmp_hdr_t* hdr = (icmp_hdr_t*)pbuf_get(pb);
  hdr->type = ICMP_ECHO;
  hdr->code = 0;
  hdr->checksum = 0;
  uint16_t* hdr_data = (uint16_t*)&hdr->hdr_data;
  hdr_data[0] = htob16(id);
  hdr_data[1] = htob16(seq);
  hdr->checksum = ip_checksum(hdr, sizeof(icmp_hdr_t));
  return pb;
}
