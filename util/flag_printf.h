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

// Utility for printing sets of flags and bit-stuffed fields.  For example,
//
// flag_spec_t FLAGS[] = {
//   { FLAG, 0x0001, 0, 0, "ABC" }, // or FLAG_SPEC_FLAG("ABC", 0x0001)
//   { FLAG, 0x0002, 0, 0, "DEF" }, // or FLAG_SPEC_FLAG("DEF", 0x0002)
//   { FLAG, 0x0004, 0, 0, "XX" },  // or FLAG_SPEC_FLAG("XX", 0x0004)
//   { FIELD, 0, 0xF0, 4, "TYPE" }, // or FLAG_SPEC_FIELD("TYPE", 0xF0, 4)
//                                  // or FLAG_SPEC_FIELD2("TYPE", 4, 4)
//   { 0x0, 0x0, 0x0, 0x0, 0x0 },   // or FLAG_SPEC_END
// };
//
// ....
//
// flag_sprintf(buf, 0x65, FLAGS);
//
// yields the string "[ ABC XX TYPE(6) ]"
#ifndef APOO_UTIL_FLAG_PRINTF_H
#define APOO_UTIL_FLAG_PRINTF_H

#include <stdint.h>

enum flag_spec_type {
  FLAG,   // A bit flag, which can be either on or off.
  FIELD,  // A bit-stuffed field, with an offset and mask.
};
typedef enum flag_spec_type flag_spec_type_t;

// A flag spec.  Can be either a flag or a field.  If a flag, then when the
// corresponding bits are set in the value, the flag name is printed.  If a
// field, then the bits with the given mask and offset are extracted from the
// value and printed.
//
// A flag can optionally set an "alternate" name that will be printed if the
// flag *isn't* set (instead of simply omitting the flag).
struct flag_spec {
  flag_spec_type_t type;
  uint64_t flag;  // If type == FLAG.
  uint64_t field_mask;  // If type == FIELD.
  uint64_t field_offset;  // If type == FIELD.
  const char* name;
  const char* alternate_name;
};
typedef struct flag_spec flag_spec_t;

// Convenience macros for defining flag_spec_ts in a list.
#define FLAG_SPEC_FLAG(name, flag) { FLAG, (flag), 0, 0, (name), 0x0 }
#define FLAG_SPEC_FLAG2(name, alt_name, flag) { FLAG, (flag), 0, 0, (name), (alt_name) }
#define FLAG_SPEC_FIELD(name, mask, offset) { FIELD, 0, (mask), (offset), (name), 0x0 }
#define FLAG_SPEC_FIELD2(name, size_bits, offset) { FIELD, 0, (((1ll << (size_bits)) - 1) << (offset)), (offset), (name), 0x0 }
#define FLAG_SPEC_END { 0, 0, 0, 0, 0, 0 }

// Find all the flags present in a value and produce a string describing them.
int flag_sprintf(char* buf, uint64_t value, flag_spec_t* flags);

#endif
