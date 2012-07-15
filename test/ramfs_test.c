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

#include <stdarg.h>
#include <stdint.h>

#include "common/kassert.h"
#include "kmalloc.h"
#include "test/ktest.h"
#include "vfs/dirent.h"
#include "vfs/ramfs.h"
#include "vfs/vfs.h"

static fs_t* g_fs = 0;
static vnode_t* g_root = 0;

// Allocate, initialize, and return a vnode for the given inode.
static vnode_t* get_vnode(int inode) {
  vnode_t* n = g_fs->alloc_vnode(g_fs);
  n->num = inode;
  n->refcount = 1;
  kstrcpy(n->fstype, "ramfs");
  n->fs = g_fs;

  if (g_fs->get_vnode(n) != 0) {
    kfree(n);
    return 0;
  }
  return n;
}

static void basic_test() {
  KTEST_BEGIN("basic read/write test");
  int vnode_num = g_fs->create(g_root, "testA");
  vnode_t* n = get_vnode(vnode_num);

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

  KEXPECT_GE(g_fs->unlink(g_root, "testA"), 0);
}

// TODO(aoates): get_vnode test


// Check that the dirents returned by getdents() on the given node match the
// expected.  Note: you must pass 2*n arguments, alternating name (const char*)
// and vnodes (int).
void EXPECT_DIRENTS(vnode_t* node, int n, ...) {
  va_list args;
  va_start(args, n);

  int expected_idx = 0;
  const char* expected_name = 0;
  int expected_vnode = 0;

  const int BUFSIZE = 300;
  char dirents_buf[BUFSIZE];
  int result = 0;
  int offset = 0;
  int dirents_seen = 0;
  result = node->fs->getdents(node, offset, dirents_buf, BUFSIZE);
  while (result > 0) {
    int bufidx = 0;
    while (bufidx < result) {
      dirent_t* d = (dirent_t*)&dirents_buf[bufidx];
      offset = d->offset;
      dirents_seen++;
      if (expected_idx < n) {
        expected_name = va_arg(args, const char*);
        expected_vnode = va_arg(args, int);
        KEXPECT_STREQ(expected_name, d->name);
        KEXPECT_EQ(expected_vnode, d->vnode);

        expected_idx++;
      }

      bufidx += d->length;
    }

    // Read another chunk.
    result = node->fs->getdents(node, offset, dirents_buf, BUFSIZE);
  }
  KEXPECT_EQ(n, dirents_seen);

  va_end(args);
}

static void directory_test() {
  KTEST_BEGIN("empty directory getdents() test");
  vnode_t* n = g_root;
  EXPECT_DIRENTS(n, 2, ".", n->num, "..", n->num);

  KTEST_BEGIN("mkdir() test");
  int dir_vnode = g_fs->mkdir(g_root, "test_dir");
  KEXPECT_GE(dir_vnode, 0);
  n = get_vnode(dir_vnode);
  KEXPECT_NE(0, (uint32_t)n);

  KTEST_BEGIN("create() test");
  vnode_t* file = get_vnode(g_fs->create(n, "file1"));

  // TODO(aoates): verify link counts.
  EXPECT_DIRENTS(n, 3, ".", n->num, "..", g_root->num, "file1", file->num);

  // Create another file.
  vnode_t* file2 = get_vnode(g_fs->create(n, "file2"));
  EXPECT_DIRENTS(n, 4, ".", n->num, "..", g_root->num,
                 "file1", file->num, "file2", file2->num);

  // TODO(aoates): test relinking the same file.

  // TODO(aoates): test reading multiple dirents with several sequential calls
  // to getdents() with increasing offsets.

  KTEST_BEGIN("unlink() test");
  g_fs->unlink(n, "file1");
  EXPECT_DIRENTS(n, 3, ".", n->num, "..", g_root->num, "file2", file2->num);

  // TODO(aoates): check link count
}

void ramfs_test() {
  KTEST_SUITE_BEGIN("ramfs()");
  g_fs = ramfs_create_fs();
  g_root = get_vnode(g_fs->get_root(g_fs));

  basic_test();
  directory_test();
}
