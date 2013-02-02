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

#ifndef APOO_FILE_H
#define APOO_FILE_H

#include "kmalloc.h"

struct vnode;

// Represents an open file on the VFS.  There may be multiple file_t's per vnode
// (if multpile calls to vfs_open() are made), and multiple file descriptors per
// file_t (if dup() is called).  Moreover, a given file_t might be shared across
// multiple processes.
struct file {
  struct vnode* vnode;
  int refcount;
  int pos;  // Current position within the vnode.
  uint32_t mode;
};
typedef struct file file_t;

// Initialize a file_t with sane values.
void file_init_file(file_t* f);

// Allocate and free a file.  For now, these just call kmalloc() and kfree(),
// but we cloud replace them with a better allocator in the future.
static inline file_t* file_alloc() {
  return (file_t*)kmalloc(sizeof(file_t));
}

static inline void file_free(file_t* f) {
  kfree(f);
}

#endif
