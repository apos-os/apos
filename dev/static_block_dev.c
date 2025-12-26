// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "dev/static_block_dev.h"

#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "user/include/apos/errors.h"

static int stblk_read(struct block_dev* dev, size_t offset, void* buf,
                      size_t len, int flags) {
  stblk_dev_t* st = (stblk_dev_t*)dev->dev_data;
  KASSERT(len % STATIC_BLOCK_BLKSZ == 0);
  char* dst = buf;
  for (size_t i = 0; i < len / STATIC_BLOCK_BLKSZ; ++i) {
    void* val;
    if (htbl_get(&st->blocks, offset + i, &val) == 0) {
      kmemcpy(dst, val, STATIC_BLOCK_BLKSZ);
    } else {
      kmemset(dst, 0, STATIC_BLOCK_BLKSZ);
    }
    dst += STATIC_BLOCK_BLKSZ;
  }
  return len;
}

static int stblk_write(struct block_dev* dev, size_t offset, const void* buf,
                       size_t len, int flags) {
  return -ENXIO;
}

stblk_dev_t* stblk_create(const stblk_spec_t* s) {
  stblk_dev_t* st = KMALLOC(stblk_dev_t);
  st->dev.sectors = s->total_blocks;
  st->dev.sector_size = STATIC_BLOCK_BLKSZ;
  st->dev.dev_data = st;
  st->dev.read = &stblk_read;
  st->dev.write = &stblk_write;

  st->block_data = s->block_data;
  htbl_init(&st->blocks, s->block_map_len);  // Initialize for a 50% load factor.

  KASSERT(s->block_map_len % 2 == 0);
  for (int i = 0; i < s->block_map_len / 2; ++i) {
    int blk_idx = s->block_map[i * 2];
    int blk_data_idx = s->block_map[i * 2 + 1];
    htbl_put(&st->blocks, blk_idx, (void*)&s->block_data[blk_data_idx]);
  }

  return st;
}

void stblk_destroy(stblk_dev_t* st) {
  htbl_cleanup(&st->blocks);
  kfree(st);
}
