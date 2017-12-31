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

#include "net/pbuf.h"

#include "common/kassert.h"
#include "memory/kmalloc.h"

pbuf_t* pbuf_create(size_t headers_reserve, size_t len) {
  KASSERT(headers_reserve + len > 0);
  pbuf_t* pb = (pbuf_t*)kmalloc(sizeof(pbuf_t) + headers_reserve + len);
  if (!pb) {
    return NULL;
  }
  pb->reserved = headers_reserve;
  pb->total_len = headers_reserve + len;
  return pb;
}

void pbuf_free(pbuf_t* pb) {
  kfree(pb);
}

void* pbuf_get(pbuf_t* pb) {
  return &pb->data[pb->reserved];
}

size_t pbuf_size(const pbuf_t* pb) {
  return pb->total_len - pb->reserved;
}

void pbuf_push_header(pbuf_t* pb, size_t n) {
  // TODO(aoates): handle this more gracefully.
  KASSERT(pb->reserved >= n);
  pb->reserved -= n;
}

void pbuf_pop_header(pbuf_t* pb, size_t n) {
  KASSERT(pb->total_len - pb->reserved >= n);
  pb->reserved += n;
}
