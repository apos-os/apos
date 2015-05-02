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

#include "vfs/vfs_util.h"

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/math.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"
#include "vfs/vnode_hash.h"
#include "vfs/vfs_internal.h"

typedef struct {
  int offset;
  int bytes_ignored;
  int bytes_written;
  char* buf;
  int buflen;
} state_t;

static void vfs_print_vnode_cache_iter(void* arg, uint32_t key, void* val) {
  vnode_t* vnode = (vnode_t*)val;
  KASSERT_DBG(key == vnode_hash_n(vnode));
  char buf[1024];
  const int printlen = ksprintf(
      buf, "  %p { fs: %d inode: %d  type: %s  len: %d  refcount: %d }\n",
      vnode, vnode->fs->id, vnode->num, VNODE_TYPE_NAME[vnode->type],
      vnode->len, vnode->refcount);


  state_t* state = (state_t*)arg;
  int remove_from_start =
      max(0, state->offset - state->bytes_ignored - state->bytes_written);
  remove_from_start = min(remove_from_start, printlen);

  int bytes_to_copy = min(printlen, state->buflen);
  bytes_to_copy = min(bytes_to_copy, printlen - remove_from_start);

  kstrncpy(state->buf, buf + remove_from_start, bytes_to_copy);

  state->bytes_ignored += remove_from_start;
  state->buf += bytes_to_copy;
  state->buflen -= bytes_to_copy;
  state->bytes_written += bytes_to_copy;
}

int vfs_print_vnode_cache(int offset, char* buf, int buflen) {
  state_t state;
  state.offset = offset;
  state.bytes_ignored = 0;
  state.bytes_written = 0;
  state.buf = buf;
  state.buflen = buflen;

  htbl_iterate(&g_vnode_cache, &vfs_print_vnode_cache_iter, &state);
  return state.bytes_written;
}
