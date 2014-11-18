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

// Directory entries.
#ifndef APOO_USER_VFS_DIRENT_H
#define APOO_USER_VFS_DIRENT_H

#include "user/posix_types.h"

// A single directory entry, as produced by a concrete filesystem.
struct dirent {
  ino_t d_ino;  // vnode number
  off_t d_offset;  // Offset from *start* of directory to the next dirent_t.
  off_t d_length;  // Length of this dirent_t
  char d_name[];  // Null-terminated filename
};
typedef struct dirent dirent_t;

#endif
