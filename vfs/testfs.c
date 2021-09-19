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

#include "vfs/testfs.h"

#include <limits.h>

#include "common/errno.h"
#include "common/kstring.h"
#include "vfs/cbfs.h"

static int testfs_read_error(fs_t* fs, void* arg, int vnode, int offset,
                             void* buf, int buflen) {
  return -EIO;
}

fs_t* testfs_create(void) {
  fs_t* fs = cbfs_create("testfs", NULL, NULL, NULL, INT_MAX);
  if (!fs) return NULL;

  int result =
      cbfs_create_file(fs, "read_error", &testfs_read_error, NULL, VFS_S_IRWXU);
  if (result) goto error;

  return fs;

error:
  fs->destroy_fs(fs);
  return NULL;
}

int testfs_create_path(const char* source, unsigned long flags,
                       const void* data, size_t data_len, fs_t** fs_out) {
  if (kstrcmp(source, "") != 0) {
    return -EINVAL;
  }

  *fs_out = testfs_create();
  return 0;
}
