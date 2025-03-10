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

#include "common/refcount.h"
#include "common/types.h"
#include "memory/kmalloc.h"

struct vnode;

// Represents an open file on the VFS.  There may be multiple file_t's per vnode
// (if multpile calls to vfs_open() are made), and multiple file descriptors per
// file_t (if dup() is called).  Moreover, a given file_t might be shared across
// multiple processes.
struct file {
  int index;  // Index in the global file table.
  struct vnode* vnode;
  refcount_t refcount;  // Interrupt-safe refcount is overkill.
  koff_t pos;  // Current position within the vnode.
  kmode_t mode;
  int flags;
};
typedef struct file file_t;

// Allocate (and initialize) and free a file.
file_t* file_alloc(void);
void file_free(file_t* f);

// A file descriptor.
typedef struct {
  int file;  // Index into the global file table.
  int flags;
} fd_t;

#endif
