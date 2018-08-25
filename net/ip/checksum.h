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

#ifndef APOO_NET_IP_CHECKSUM_H
#define APOO_NET_IP_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

// Calculates the internet checksum (RFC 1071) of the given buffer.
//
// The result should not be adjusted for endianness---through the magic of Math,
// the checksum will end up (when written out as a uint16_t) matching the
// endianness of the input data.
uint16_t ip_checksum(const void* buf, size_t len);
uint16_t ip_checksum2(const void* buf, size_t len, const void* buf2,
                      size_t len2);

#endif
