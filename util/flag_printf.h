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

// Utility for printing sets of flags.  For example,
//
// flag_spec_t FLAGS[] = {
//   { 0x0001, "ABC" },
//   { 0x0002, "DEF" },
//   { 0x0004, "XX" },
//   { 0x0, 0x0 },
// };
//
// ....
//
// flag_sprintf(buf, 0x5, FLAGS);
//
// yields the string "[ ABC XX ]"
#ifndef APOO_UTIL_FLAG_PRINTF_H
#define APOO_UTIL_FLAG_PRINTF_H

// A flag spec.
struct flag_spec {
  uint32_t flag;
  const char* name;
};
typedef struct flag_spec flag_spec_t;

// Find all the flags present in a value and produce a string describing them.
int flag_sprintf(char* buf, uint32_t value, flag_spec_t* flags);

#endif
