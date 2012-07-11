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

#include <stdint.h>

#include "common/kassert.h"
#include "kmalloc.h"
#include "test/ktest.h"
#include "vfs/dirent.h"
#include "vfs/ramfs.h"
#include "vfs/vfs.h"

static fs_t* g_fs = 0;

static void basic_test() {
  KTEST_BEGIN("basic read/write test");
  vnode_t* n = g_fs->alloc_vnode(g_fs);
  KEXPECT_EQ(0, n->len);

  // Empty read test.
  char buf[100];
  int result = g_fs->read(n, 0, buf, 100);
  KEXPECT_EQ(0, result);

  result = g_fs->read(n, 10, buf, 100);
  KEXPECT_EQ(0, result);

  // Write some stuff.
  result = g_fs->write(n, 0, "abcde", 5);
  KEXPECT_EQ(5, result);
  KEXPECT_EQ(5, n->len);

  // Read it back.
  result = g_fs->read(n, 0, buf, 100);
  buf[result] = '\0';
  KEXPECT_EQ(5, result);
  KEXPECT_STREQ(buf, "abcde");

  KTEST_BEGIN("read offset test");
  // Try an offset.
  result = g_fs->read(n, 2, buf, 100);
  buf[result] = '\0';
  KEXPECT_EQ(3, result);
  KEXPECT_STREQ(buf, "cde");

  KTEST_BEGIN("read buffer size test");
  // Try a buffer size restriction.
  result = g_fs->read(n, 0, buf, 3);
  buf[result] = '\0';
  KEXPECT_EQ(3, result);
  KEXPECT_STREQ(buf, "abc");

  result = g_fs->read(n, 1, buf, 3);
  buf[result] = '\0';
  KEXPECT_EQ(3, result);
  KEXPECT_STREQ(buf, "bcd");

  KTEST_BEGIN("read past end of buffer test");
  result = g_fs->read(n, 10, buf, 100);
  buf[result] = '\0';
  KEXPECT_EQ(0, result);
  KEXPECT_STREQ(buf, "");

  KTEST_BEGIN("overwrite test");
  result = g_fs->write(n, 0, "ABC", 3);
  KEXPECT_EQ(3, result);

  result = g_fs->read(n, 0, buf, 100);
  buf[result] = '\0';
  KEXPECT_EQ(5, result);
  KEXPECT_STREQ(buf, "ABCde");

  KTEST_BEGIN("write offset test");
  result = g_fs->write(n, 2, "xy", 2);
  KEXPECT_EQ(2, result);

  result = g_fs->read(n, 0, buf, 100);
  buf[result] = '\0';
  KEXPECT_EQ(5, result);
  KEXPECT_STREQ(buf, "ABxye");
  KEXPECT_EQ(5, n->len);

  KTEST_BEGIN("write past end of file test");
  result = g_fs->write(n, 10, "1234", 4);
  KEXPECT_EQ(4, result);
  KEXPECT_EQ(14, n->len);

  result = g_fs->read(n, 0, buf, 100);
  KEXPECT_EQ(14, result);
  KEXPECT_EQ('A', buf[0]);
  KEXPECT_EQ('B', buf[1]);
  KEXPECT_EQ('x', buf[2]);
  KEXPECT_EQ('y', buf[3]);
  KEXPECT_EQ('e', buf[4]);
  for (int i = 5; i < 10; ++i) {
    KEXPECT_EQ('\0', buf[i]);
  }
  KEXPECT_EQ('1', buf[10]);
  KEXPECT_EQ('2', buf[11]);
  KEXPECT_EQ('3', buf[12]);
  KEXPECT_EQ('4', buf[13]);
}

// TODO(aoates): get_vnode test

static void directory_test() {
  KTEST_BEGIN("empty directory getdents() test");
  vnode_t* n = g_fs->alloc_vnode(g_fs);
  n->type = VNODE_DIRECTORY;

  uint8_t dirent_buf[300];
  int result = g_fs->getdents(n, 0, &dirent_buf[0], 300);
  KEXPECT_EQ(0, result);

  KTEST_BEGIN("empty directory w/ offset getdents() test");
  result = g_fs->getdents(n, 25, &dirent_buf[0], 300);
  KEXPECT_EQ(0, result);

  KTEST_BEGIN("link() test");
  vnode_t* file = g_fs->alloc_vnode(g_fs);
  g_fs->link(n, file, "file1");

  // TODO(aoates): verify link counts.

  result = g_fs->getdents(n, 0, &dirent_buf[0], 300);
  KEXPECT_GT(result, 0);

  dirent_t* d = (dirent_t*)(&dirent_buf[0]);
  KEXPECT_EQ(d->vnode, file->num);
  KEXPECT_EQ(d->length, result);
  KEXPECT_STREQ(d->name, "file1");

  // Link another file.
  vnode_t* file2 = g_fs->alloc_vnode(g_fs);
  g_fs->link(n, file2, "file2");

  result = g_fs->getdents(n, 0, &dirent_buf[0], 300);
  KEXPECT_GT(result, 0);

  d = (dirent_t*)(&dirent_buf[0]);
  KEXPECT_EQ(d->vnode, file->num);
  KEXPECT_STREQ(d->name, "file1");
  KEXPECT_GT(result, d->length + sizeof(dirent_t));

  dirent_t* d2 = (dirent_t*)((uint8_t*)d + d->length);
  KEXPECT_EQ(d2->vnode, file2->num);
  KEXPECT_STREQ(d2->name, "file2");
  KEXPECT_EQ(result, d->length + d2->length);

  // TODO(aoates): test relinking the same file.

  // TODO(aoates): test reading multiple dirents with several sequential calls
  // to getdents() with increasing offsets.
}

void ramfs_test() {
  KTEST_SUITE_BEGIN("ramfs()");
  g_fs = ramfs_create();

  basic_test();
  directory_test();
}
