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

#ifndef APOO_NET_IP_ICMPV6_NDP_INTERNAL_H
#define APOO_NET_IP_ICMPV6_NDP_INTERNAL_H

#include "common/types.h"

// A parsed NDP option.
typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t len;
  uint8_t value[];
} ndp_option_t;

// Parse and validate a series of options.  Fills the option array with pointers
// with up to |max_opts| options.  Returns the total number of options (which
// may be higher than |max_opts|), or -error.
int ndp_parse_opts(const uint8_t* buf, size_t len, const ndp_option_t** opts,
                   int max_opts);

#endif
