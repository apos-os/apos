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

#include "vfs/file.h"

static void file_init_file(file_t* f) {
  f->index = -1;
  f->vnode = 0x0;
  f->refcount = 0;
  f->pos = 0;
  f->mode = 0xFF;  // A bad mode.
  f->flags = 0;
}

file_t* file_alloc(void) {
  file_t* f = KMALLOC(file_t);
  if (f) {
    file_init_file(f);
  }
  return f;
}

void file_free(file_t* f) {
  kfree(f);
}
