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

#ifndef APOO_NET_IP_ICMPV6_MULTICAST_H
#define APOO_NET_IP_ICMPV6_MULTICAST_H

#include "net/ip/icmpv6/protocol.h"
#include "user/include/apos/net/socket/inet.h"

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint16_t max_response_code;
  uint16_t reserved;
  struct in6_addr multicast_addr;
  uint8_t s_qrv;
  uint8_t qqic;
  uint16_t num_sources;
  struct in6_addr sources[];
} mld_query_t;

typedef struct __attribute__((packed)) {
  uint8_t record_type;
  uint8_t aux_data_len;
  uint16_t num_sources;
  struct in6_addr multicast_addr;
  struct in6_addr sources[];
} mld_multicast_record_t;

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint16_t reserved;
  uint16_t num_mc_records;
  mld_multicast_record_t records[];
} mld_listener_report_t;

#define MLD_MODE_IS_INCLUDE 1
#define MLD_MODE_IS_EXCLUDE 2
#define MLD_CHANGE_TO_INCLUDE_MODE 3
#define MLD_CHANGE_TO_EXCLUDE_MODE 4

#endif
