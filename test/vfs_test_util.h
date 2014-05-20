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

#ifndef APOO_TEST_VFS_TEST_UTIL_H
#define APOO_TEST_VFS_TEST_UTIL_H

#include "vfs/stat.h"
#include "vfs/vfs.h"
#include "test/ktest.h"

// Convert a "rwxr-xrw-"-style string into a mode_t.
mode_t str_to_mode(const char* mode_str);

// Create the given file with the given mode.
void create_file(const char* path, const char* mode);

// Helper method that verifies that the given file can be created (then unlinks
// it).
static void EXPECT_CAN_CREATE_FILE(const char* path) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    vfs_close(fd);
    vfs_unlink(path);
  }
}

// Helper method that verifies the given file exists.
static void EXPECT_FILE_EXISTS(const char* path) {
  // The file should still exist.
  const int fd = vfs_open(path, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    KEXPECT_EQ(0, vfs_close(fd));
  }
}

static void EXPECT_FILE_DOESNT_EXIST(const char* path) {
  const int fd = vfs_open(path, VFS_O_RDWR);
  KEXPECT_EQ(-ENOENT, fd);
  if (fd >= 0) vfs_close(fd);
}

// Run vfs_getdents() on the given fd and verify it matches the given set of
// dirents.
// TODO(aoates): actually verify the vnode numbers vfs_getdents returns.
typedef struct {
  int vnode;
  const char* name;
} edirent_t;
void EXPECT_GETDENTS(int fd, int expected_num, edirent_t expected[]);

#endif
