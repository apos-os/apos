// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_PBUF_H
#define APOO_NET_PBUF_H

#include <stddef.h>

// A flexible packet buffer that allows header manipulation as it moves up and
// down the stack.  Each pbuf has an underlying buffer that consists of some
// reserved space for future headers followed by the data buffer.  Clients can
// use pbuf_push_header() and pbuf_pop_header() to "add" space to the start of
// the data buffer (or remove it).
//
// Example (not to scale):
//
// pbuf_create(16, 32) creates a 32-byte buffer backed by a 48-byte larger
// buffer:
//   | <16 bytes> | <32 bytes>    |
//   |  reseved   |    data       |
//                ^ pbuf_get() returns this
//
// After pbuf_push_header(3),
//   | <13 b>  | <35 bytes>       |
//   | reseved |    data          |
//             ^ pbuf_get() returns this
//
// After pbuf_pop_header(7),
//   | <20 bytes >  | <28 bytes>  |
//   | reseved      |    data     |
//                  ^ pbuf_get() returns this
struct pbuf;
typedef struct pbuf pbuf_t;

// Allocate a pbuf of the given size.  Reserves |headers_reserve| bytes at the
// start of the buffer for future headers.
pbuf_t* pbuf_create(size_t headers_reserve, size_t len);

// Free the given pbuf.
void pbuf_free(pbuf_t* pb);

// Returns the data portion of the pbuf.
void* pbuf_get(pbuf_t* pb);

// Returns the size of the data portion of the pbuf.
size_t pbuf_size(const pbuf_t* pb);

// Adds |n| bytes to the front of the pbuf from the reserved portion.  The
// contents of the prefix is unspecified, unless it was previously popped with
// pbuf_pop_header() (in which case it's unchanged).
// TODO(aoates): handle failure scenarios more gracefully.  Should we just
// always reallocate?
void pbuf_push_header(pbuf_t* pb, size_t n);

// Removes |n| bytes from the front of the pbuf, adding it back to the reserved
// portion.  Any data in the the popped section can be accessed later by
// re-pushing it.
void pbuf_pop_header(pbuf_t* pb, size_t n);

#endif
