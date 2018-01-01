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

#ifndef APOO_NET_ICMP_H
#define APOO_NET_ICMP_H

#include <stdint.h>

#include "net/pbuf.h"

// ICMP packet header.
typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t hdr_data[4];
} icmp_hdr_t;

typedef enum {
  ICMP_ECHO_REPLY = 0,
  ICMP_ECHO = 8,
} icmp_type_t;

// Make an ICMP echo message (request).
pbuf_t* icmp_mkecho(uint16_t id, uint16_t seq);

#endif
