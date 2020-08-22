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

kmode_t str_to_mode(const char* mode_str) {
  KASSERT(kstrlen(mode_str) == 9);
  for (int i = 0; i < 9; ++i) {
    KASSERT(mode_str[i] == 'r' || mode_str[i] == 'w' || mode_str[i] == 'x' ||
            mode_str[i] == '-');
  }

  kmode_t mode = 0;
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

int compare_dirents(int fd, int expected_num, const edirent_t expected[]) {
  const int kBufSize = sizeof(kdirent_t) * 3;  // Ensure we have several calls.
  char buf[kBufSize];
  int num_dirents = 0;

  while (1) {
    const int len = vfs_getdents(fd, (kdirent_t*)(&buf[0]), kBufSize);
    if (len < 0) {
      KEXPECT_GE(len, -0);
      break;
    }
    if (len == 0) {
      break;
    }

    int buf_offset = 0;
    do {
      kdirent_t* ent = (kdirent_t*)(&buf[buf_offset]);
      num_dirents++;
      buf_offset += ent->d_reclen;

      KLOG("dirent: %lu -> %s\n", ent->d_ino, ent->d_name);

      // Ignore the root lost+found, dev, and proc directories.
      if (kstrcmp(ent->d_name, "lost+found") == 0 ||
          kstrcmp(ent->d_name, "bin") == 0 ||
          kstrcmp(ent->d_name, "dev") == 0 ||
          kstrcmp(ent->d_name, "proc") == 0) {
        num_dirents--;
        continue;
      }

      // Make sure the dirent matches one of the expected.
      int i;
      for (i = 0; i < expected_num; ++i) {
        if (kstrcmp(ent->d_name, expected[i].name) == 0) {
          break;
        }
      }
      if (i == expected_num) {
        KLOG("Error: dirent <%lu, %s> doesn't match any expected dirents\n",
             ent->d_ino, ent->d_name);
        return 1;
      }
    } while (buf_offset < len);
  }

  if (expected_num != num_dirents) {
    KLOG("Error: expected %d dirents, but found %d\n",
         expected_num, num_dirents);
    return 1;
  } else {
    return 0;
  }
}

int compare_dirents_p(const char* path, int expected_num,
                      const edirent_t expected[]) {
  int fd = vfs_open(path, VFS_O_RDONLY);
  if (fd < 0) return fd;
  int result = compare_dirents(fd, expected_num, expected);
  vfs_close(fd);
  return result;
}
