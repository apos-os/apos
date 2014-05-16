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

#include "test/vfs_test_util.h"

#include "common/kassert.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

mode_t str_to_mode(const char* mode_str) {
  KASSERT(kstrlen(mode_str) == 9);
  for (int i = 0; i < 9; ++i) {
    KASSERT(mode_str[i] == 'r' || mode_str[i] == 'w' || mode_str[i] == 'x' ||
            mode_str[i] == '-');
  }

  mode_t mode = 0;
  if (mode_str[0] == 'r') mode |= VFS_S_IRUSR;
  if (mode_str[1] == 'w') mode |= VFS_S_IWUSR;
  if (mode_str[2] == 'x') mode |= VFS_S_IXUSR;
  if (mode_str[3] == 'r') mode |= VFS_S_IRGRP;
  if (mode_str[4] == 'w') mode |= VFS_S_IWGRP;
  if (mode_str[5] == 'x') mode |= VFS_S_IXGRP;
  if (mode_str[6] == 'r') mode |= VFS_S_IROTH;
  if (mode_str[7] == 'w') mode |= VFS_S_IWOTH;
  if (mode_str[8] == 'x') mode |= VFS_S_IXOTH;

  return mode;
}

void create_file(const char* path, const char* mode) {
  int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR, str_to_mode(mode));
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
}
