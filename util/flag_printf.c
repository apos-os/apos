// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include "common/kstring.h"
#include "common/kprintf.h"
#include "util/flag_printf.h"

int flag_sprintf(char* buf, uint64_t value, const flag_spec_t* flags) {
  int idx = 0;
  kstrcpy(buf, "[ ");
  idx += 2;
  while (flags->name != 0x0) {
    if (flags->type == FLAG && flags->flag & value) {
      idx += ksprintf(buf + idx, "%s ", flags->name);
    } else if (flags->type == FLAG && flags->alternate_name != 0x0) {
      idx += ksprintf(buf + idx, "%s ", flags->alternate_name);
    } else if (flags->type == FIELD) {
      uint32_t fieldval = (value & flags->field_mask) >> flags->field_offset;
      idx += ksprintf(buf + idx, "%s(%d) ", flags->name, fieldval);
    }
    flags++;
  }
  kstrcpy(buf + idx, "]");
  idx++;
  return idx;
}
