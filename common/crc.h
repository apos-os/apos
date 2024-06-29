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

#ifndef APOO_COMMON_CRC_H
#define APOO_COMMON_CRC_H

#include "common/types.h"

// Standard networking CRC32 polynomial.
#define CRC32_NET_POLY 0xedb88320

// Calculate a 32-bit CRC.  Calculates per the Ethernet CRC parameters (reversed
// polynomial, reflected bit order, etc).
uint32_t crc32(const uint8_t* msg, size_t len, uint32_t poly);

#endif
