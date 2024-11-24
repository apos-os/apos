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

#ifndef APOO_COMMON_CIRCBUF_H
#define APOO_COMMON_CIRCBUF_H

#include <stddef.h>
#include <stdint.h>

#include "user/include/apos/posix_types.h"

typedef struct {
  void* buf;
  size_t buflen;  // Length of the buffer overall.
  size_t pos;  // Start position of the data in the buffer.
  size_t len;  // Length of the data in the buffer.
  uint16_t generation;
} circbuf_t;

void circbuf_init(circbuf_t* cbuf, void* buf, size_t buflen);

ssize_t circbuf_read(circbuf_t* cbuf, void* buf, size_t nbytes);
ssize_t circbuf_write(circbuf_t* cbuf, const void* buf, size_t nbytes);

// Peek (read without consuming) and consume (consume without reading) data.
// circbuf_read(n) is equivalent to circbuf_peek(0, n) followed by
// circbuf_consume().
ssize_t circbuf_peek(const circbuf_t* cbuf, void* buf, size_t offset,
                     size_t nbytes);
ssize_t circbuf_consume(circbuf_t* cbuf, size_t nbytes);

// Empty the buffer.
void circbuf_clear(circbuf_t* cbuf);

// Returns the free capacity of the circbuf.
size_t circbuf_available(const circbuf_t* cbuf);

#endif
