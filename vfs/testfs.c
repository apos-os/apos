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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "common/math.h"
#include "user/vfs/dirent.h"

static vnode_t* testfs_alloc_vnode(struct fs* fs);
static int testfs_get_root(struct fs* fs);
static int testfs_get_vnode(vnode_t* vnode);
static int testfs_put_vnode(vnode_t* vnode);
static int testfs_lookup(vnode_t* parent, const char* name);
static int testfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev);
static int testfs_mkdir(vnode_t* parent, const char* name);
static int testfs_rmdir(vnode_t* parent, const char* name);
static int testfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int testfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize);
static int testfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int testfs_unlink(vnode_t* parent, const char* name);
static int testfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int testfs_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int testfs_read_page(vnode_t* vnode, int page_offset, void* buf);
static int testfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

fs_t* testfs_create(void) {
  fs_t* f = (fs_t*)kmalloc(sizeof(fs_t));
  vfs_fs_init(f);

  kstrcpy(f->fstype, "testfs");
  f->alloc_vnode = &testfs_alloc_vnode;
  f->get_root = &testfs_get_root;
  f->get_vnode = &testfs_get_vnode;
  f->put_vnode = &testfs_put_vnode;
  f->lookup = &testfs_lookup;
  f->mknod = &testfs_mknod;
  f->mkdir = &testfs_mkdir;
  f->rmdir = &testfs_rmdir;
  f->read = &testfs_read;
  f->write = &testfs_write;
  f->link = &testfs_link;
  f->unlink = &testfs_unlink;
  f->getdents = &testfs_getdents;
  f->stat = &testfs_stat;
  f->read_page = &testfs_read_page;
  f->write_page = &testfs_write_page;

  return f;
}

void testfs_free(fs_t* fs) {
  kfree(fs);
}

static vnode_t* testfs_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int testfs_get_root(struct fs* fs) {
  return 0;
}

static int testfs_get_vnode(vnode_t* vnode) {
  KASSERT(vnode->num == 0);
  vnode->type = VNODE_DIRECTORY;
  vnode->uid = 0;
  vnode->gid = 0;
  vnode->mode = VFS_S_IRUSR | VFS_S_IXUSR;
  kstrcpy(vnode->fstype, "testfs");
  return 0;
}

static int testfs_put_vnode(vnode_t* vnode) {
  KASSERT(vnode->num == 0);
  return 0;
}

static int testfs_lookup(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  if (kstrcmp(name, ".") == 0 || kstrcmp(name, "..") == 0) {
    return 0;
  } else {
    return -ENOENT;
  }
}

static int testfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int testfs_mkdir(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int testfs_rmdir(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int testfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(vnode->num == 0);
  return -EISDIR;
}

static int testfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize) {
  KASSERT(vnode->num == 0);
  return -EISDIR;
}

static int testfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int testfs_unlink(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int testfs_getdents(vnode_t* vnode, int offset, void* outbuf,
                           int outbufsize) {
  KASSERT(vnode->num == 0);

  const int kBufLen = 2 * sizeof(dirent_t) + 2 + 3;
  char buf[kBufLen];
  dirent_t* d = (dirent_t*)(&buf[0]);
  d->d_ino = 0;
  d->d_offset = sizeof(dirent_t) + 2;
  d->d_length = d->d_offset;
  kstrcpy(d->d_name, ".");

  d = (dirent_t*)(&buf[d->d_offset]);
  d->d_ino = 0;
  d->d_offset = kBufLen;
  d->d_length = sizeof(dirent_t) + 3;
  kstrcpy(d->d_name, "..");

  if (offset >= kBufLen) return 0;
  int len = min(kBufLen, outbufsize);
  kmemcpy(outbuf, buf + offset, len);
  return len;
}

static int testfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  KASSERT(vnode->num == 0);
  stat_out->st_mode = VFS_S_IFDIR | VFS_S_IRUSR | VFS_S_IXUSR;
  stat_out->st_nlink = 2;
  stat_out->st_rdev = makedev(0, 0);
  stat_out->st_size = 2 * sizeof(dirent_t) + 5;
  stat_out->st_blksize = 512;
  stat_out->st_blocks = 1;
  return 0;
}

static int testfs_read_page(vnode_t* vnode, int page_offset, void* buf) {
  return -ENOTSUP;
}

static int testfs_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  return -ENOTSUP;
}
