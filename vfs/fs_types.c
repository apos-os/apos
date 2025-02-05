// Copyright 2021 Andrew Oates.  All Rights Reserved.
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
#include "vfs/fs_types.h"

#include "common/config.h"
#include "common/errno.h"
#include "common/kstring.h"

#include "proc/procfs.h"
#include "vfs/ramfs.h"
#include "vfs/testfs.h"

#if ENABLE_EXT2
#include "vfs/ext2/ext2.h"
#endif

// A function that creates a filesystem from the given source, or returns
// -error.
typedef int (*fs_create_fn)(const char* source, unsigned long flags,
                            const void* data, size_t data_len, fs_t** fs_out);

// A filesystem type.
typedef struct {
  const char* fs_type;  // The name (e.g. "ext2").
  fs_create_fn create;  // The creation function.
} fs_entry_t;

static const fs_entry_t kFsEntries[] = {
    {"procfs", &procfs_create_path},
    {"ramfs", &ramfs_create_path},
    {"testfs", &testfs_create_path},
#if ENABLE_EXT2
    {"ext2", &ext2_create_path},
#endif
    {NULL, NULL},
};

int fs_create(const char* type, const char* source, unsigned long flags,
              const void* data, size_t data_len, fs_t** fs_out) {
  for (int i = 0; kFsEntries[i].fs_type != NULL; ++i) {
    if (kstrcmp(type, kFsEntries[i].fs_type) == 0) {
      return kFsEntries[i].create(source, flags, data, data_len, fs_out);
    }
  }

  return -EINVAL;
}
