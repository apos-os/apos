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
#include "net/mac.h"

#include "common/errno.h"
#include "common/kprintf.h"
#include "common/kstring.h"

const char* mac2str(const uint8_t mac[], char* buf) {
  ksprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
           mac[4], mac[5]);
  return buf;
}

int str2mac(const char* str, uint8_t* mac_out) {
  char seg[3];
  seg[2] = '\0';
  if (kstrlen(str) != 6 * 3 - 1) {
    return -EINVAL;
  }
  for (int i = 0; i < 6; ++i) {
    seg[0] = *str++;
    seg[1] = *str++;
    char term = *str++;
    if (i < 5 && term != ':') {  // Final NULL checked by length test.
      return -EINVAL;
    }
    if (!kishex(seg[0]) || !kishex(seg[1])) {
      return -EINVAL;
    }
    mac_out[i] = katou_hex(seg);
  }
  return 0;
}
