// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include <stdbool.h>

#include <apos/syscall_decls.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ktest.h"

typedef struct  {
  const char* name;
  ino_t inode;
  bool matched;
} expected_dirent_t;

static struct stat do_stat(const char* path) {
  struct stat result;
  KEXPECT_EQ(0, lstat(path, &result));
  return result;
}

static int do_getdents(int fd, struct dirent* buf, int count) {
  int result = getdents(fd, buf, count);
  return (result < 0) ? -errno : result;
}

#define NUM_EXPECTED 4

void fs_test(void) {
  KTEST_SUITE_BEGIN("Filesystem tests");

  KTEST_BEGIN("getdents(): basic test");
  KEXPECT_EQ(0, mkdir("_fs_test_dir", S_IRWXU));
  int fd = open("_fs_test_dir/fileA", O_CREAT | O_RDONLY, S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, close(fd));
  fd = open("_fs_test_dir/fileB", O_CREAT | O_RDONLY, S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, close(fd));

  char buffer[500];
  fd = open("_fs_test_dir", O_DIRECTORY | O_RDONLY);
  KEXPECT_GE(fd, 0);
  int result = getdents(fd, (struct dirent*)buffer, 500);
  KEXPECT_EQ(result, 4 * (1 + sizeof(struct dirent)) + strlen(".") +
                         strlen("..") + strlen("fileA") + strlen("fileB"));
  expected_dirent_t expected_dirents[NUM_EXPECTED] = {
    {".", do_stat("_fs_test_dir").st_ino, false},
    {"..", do_stat(".").st_ino, false},
    {"fileA", do_stat("_fs_test_dir/fileA").st_ino, false},
    {"fileB", do_stat("_fs_test_dir/fileB").st_ino, false},
  };

  off_t offset = 0;
  while (offset < result) {
    const struct dirent* d = (const struct dirent*)(&buffer[offset]);
    KEXPECT_EQ(d->d_reclen, sizeof(struct dirent) + strlen(d->d_name) + 1);
    for (int i = 0; i < NUM_EXPECTED; ++i) {
      if (strcmp(d->d_name, expected_dirents[i].name) == 0) {
        KEXPECT_EQ(false, expected_dirents[i].matched);
        KEXPECT_EQ(expected_dirents[i].inode, d->d_ino);
        expected_dirents[i].matched = true;
        break;
      }
      KEXPECT_LT(i, NUM_EXPECTED);
    }
    offset += d->d_reclen;
  }

  for (int i = 0; i < NUM_EXPECTED; ++i) {
    KEXPECT_EQ(true, expected_dirents[i].matched);
  }

  KTEST_BEGIN("getdents(): bad arguments test");
  KEXPECT_EQ(-EBADF, do_getdents(-5, (struct dirent*)buffer, 500));
  KEXPECT_EQ(-EFAULT, do_getdents(fd, (struct dirent*)0x0, 500));
  KEXPECT_EQ(-EFAULT, do_getdents(fd, (struct dirent*)0x89000, 500));
  KEXPECT_EQ(-EFAULT, do_getdents(fd, (struct dirent*)0xc1000000, 500));
  KEXPECT_EQ(-EFAULT, do_getdents(fd, (struct dirent*)buffer, 0xfffffff));

  // Cleanup.
  KEXPECT_EQ(0, close(fd));
  KEXPECT_EQ(0, unlink("_fs_test_dir/fileA"));
  KEXPECT_EQ(0, unlink("_fs_test_dir/fileB"));
  KEXPECT_EQ(0, rmdir("_fs_test_dir"));
}
