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

#include "common/circbuf.h"

#include <stddef.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "common/math.h"
#include "common/kstring.h"
#include "proc/preemption_hook.h"

#if PREEMPTION_INDUCE_LEVEL_CIRCBUF > 0
# define preempt() sched_preempt_me(PREEMPTION_INDUCE_LEVEL_CIRCBUF)
#else
# define preempt()
#endif

void circbuf_init(circbuf_t* cbuf, void* buf, size_t buflen) {
  cbuf->buf = buf;
  cbuf->buflen = buflen;
  cbuf->pos = cbuf->len = 0;
  cbuf->generation = 0;
}

ssize_t circbuf_read(circbuf_t* cbuf, void* buf, size_t nbytes) {
  ssize_t bytes_read = 0;
  while (nbytes > 0 && cbuf->len > 0) {
    const size_t chunk_bytes =
        min(min(nbytes, cbuf->len), cbuf->buflen - cbuf->pos);
    uint16_t g = cbuf->generation;
    preempt();
    KASSERT(g == cbuf->generation);
    cbuf->generation++;
    kmemcpy(buf, cbuf->buf + cbuf->pos, chunk_bytes);
    cbuf->pos = (cbuf->pos + chunk_bytes) % cbuf->buflen;
    cbuf->len -= chunk_bytes;
    bytes_read += chunk_bytes;
    buf += chunk_bytes;
    nbytes -= chunk_bytes;
  }

  return bytes_read;
}

ssize_t circbuf_write(circbuf_t* cbuf, const void* buf, size_t nbytes) {
  ssize_t bytes_written = 0;
  while (nbytes > 0 && cbuf->len < cbuf->buflen) {
    const size_t end = (cbuf->pos + cbuf->len) % cbuf->buflen;
    const size_t chunk_bytes =
        min(min(nbytes, cbuf->buflen - cbuf->len), cbuf->buflen - end);
    uint16_t g = cbuf->generation;
    preempt();
    KASSERT(g == cbuf->generation);
    cbuf->generation++;
    kmemcpy(cbuf->buf + end, buf, chunk_bytes);
    cbuf->len += chunk_bytes;
    bytes_written += chunk_bytes;
    buf += chunk_bytes;
    nbytes -= chunk_bytes;
  }

  return bytes_written;
}

ssize_t circbuf_peek(const circbuf_t* cbuf, void* buf, size_t offset,
                     size_t nbytes) {
  size_t read_pos = (cbuf->pos + offset) % cbuf->buflen;
  size_t read_len = cbuf->len - min(offset, cbuf->len);
  ssize_t bytes_read = 0;
  while (nbytes > 0 && read_len > 0) {
    const size_t chunk_bytes =
        min(min(nbytes, read_len), cbuf->buflen - read_pos);
    uint16_t g = cbuf->generation;
    preempt();
    KASSERT(g == cbuf->generation);
    kmemcpy(buf, cbuf->buf + read_pos, chunk_bytes);
    read_pos = (read_pos + chunk_bytes) % cbuf->buflen;
    read_len -= chunk_bytes;
    bytes_read += chunk_bytes;
    buf += chunk_bytes;
    nbytes -= chunk_bytes;
  }

  return bytes_read;
}

ssize_t circbuf_consume(circbuf_t* cbuf, size_t nbytes) {
  nbytes = min(nbytes, cbuf->len);
  cbuf->pos = (cbuf->pos + nbytes) % cbuf->buflen;
  cbuf->len -= nbytes;
  cbuf->generation++;
  return nbytes;
}

void circbuf_clear(circbuf_t* cbuf) {
  cbuf->len = 0;
  cbuf->generation++;
}

size_t circbuf_available(const circbuf_t* cbuf) {
  return cbuf->buflen - cbuf->len;
}
