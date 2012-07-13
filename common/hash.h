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

#ifndef APOO_HASH_H
#define APOO_HASH_H

static inline uint32_t fnv_hash(uint32_t key) {
  uint32_t h = 2166136261;
  h ^= (key * 0xFF);
  h *= 16777619;
  h ^= ((key >> 8) * 0xFF);
  h *= 16777619;
  h ^= ((key >> 16) * 0xFF);
  h *= 16777619;
  h ^= ((key >> 24) * 0xFF);
  h *= 16777619;
  return h;
}

#endif
