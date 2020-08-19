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

#include "common/errno.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/dev.h"
#include "memory/kmalloc.h"
#include "proc/user.h"
#include "vfs/anonfs.h"
#include "vfs/fs.h"

static vnode_t* anonfs_alloc_vnode(struct fs* fs);
static int anonfs_get_root(struct fs* fs);
static int anonfs_get_vnode(vnode_t* vnode);
static int anonfs_put_vnode(vnode_t* vnode);
static int anonfs_lookup(vnode_t* parent, const char* name);
static int anonfs_mknod(vnode_t* parent, const char* name, vnode_type_t type,
                        apos_dev_t dev);
static int anonfs_mkdir(vnode_t* parent, const char* name);
static int anonfs_rmdir(vnode_t* parent, const char* name);
static int anonfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int anonfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize);
static int anonfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int anonfs_unlink(vnode_t* parent, const char* name);
static int anonfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int anonfs_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int anonfs_symlink(vnode_t* parent, const char* name, const char* path);
static int anonfs_readlink(vnode_t* node, char* buf, int bufsize);
static int anonfs_truncate(vnode_t* node, koff_t length);
static int anonfs_read_page(vnode_t* vnode, int page_offset, void* buf);
static int anonfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

typedef struct {
  fs_t fs;
  vnode_type_t type;
  kino_t next_inode;
} anonfs_t;

fs_t* anonfs_create(vnode_type_t type) {
  anonfs_t* fs = (anonfs_t*)kmalloc(sizeof(anonfs_t));
  kmemset(fs, 0, sizeof(anonfs_t));

  kstrcpy(fs->fs.fstype, "anonfs");
  fs->fs.dev = makedev(DEVICE_ID_UNKNOWN, DEVICE_ID_UNKNOWN);
  fs->fs.open_vnodes = 0;
  fs->type = type;
  fs->next_inode = 0;

  fs->fs.alloc_vnode = &anonfs_alloc_vnode;
  fs->fs.get_root = &anonfs_get_root;
  fs->fs.get_vnode = &anonfs_get_vnode;
  fs->fs.put_vnode = &anonfs_put_vnode;
  fs->fs.lookup = &anonfs_lookup;
  fs->fs.mknod = &anonfs_mknod;
  fs->fs.mkdir = &anonfs_mkdir;
  fs->fs.rmdir = &anonfs_rmdir;
  fs->fs.read = &anonfs_read;
  fs->fs.write = &anonfs_write;
  fs->fs.link = &anonfs_link;
  fs->fs.unlink = &anonfs_unlink;
  fs->fs.getdents = &anonfs_getdents;
  fs->fs.stat = &anonfs_stat;
  fs->fs.symlink = &anonfs_symlink;
  fs->fs.readlink = &anonfs_readlink;
  fs->fs.truncate = &anonfs_truncate;
  fs->fs.read_page = &anonfs_read_page;
  fs->fs.write_page = &anonfs_write_page;

  return &fs->fs;
}

kino_t anonfs_create_vnode(fs_t* fs) {
  anonfs_t* afs = (anonfs_t*)fs;
  return afs->next_inode++;
}

static vnode_t* anonfs_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int anonfs_get_vnode(vnode_t* vnode) {
  anonfs_t* afs = (anonfs_t*)vnode->fs;
  vnode->type = afs->type;
  vnode->len = 0;
  vnode->uid = geteuid();
  vnode->gid = getegid();
  vnode->mode = VFS_S_IRWXU;
  kstrcpy(vnode->fstype, "anonfs");

  return 0;
}

static int anonfs_put_vnode(vnode_t* vnode) {
  return 0;
}

static int anonfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  // TODO(aoates): anything to do here?
  return 0;
}

#define ANONFS_UNIMPLEMENTED(name, args) \
    static int name args { \
      klogfm(KL_VFS, DFATAL, #name " unimplemented\n"); \
      return -ENOTSUP; \
    }

ANONFS_UNIMPLEMENTED(anonfs_get_root, (struct fs* fs))
ANONFS_UNIMPLEMENTED(anonfs_lookup, (vnode_t* parent, const char* name))
ANONFS_UNIMPLEMENTED(anonfs_mknod, (vnode_t* parent, const char* name, vnode_type_t type, apos_dev_t dev))
ANONFS_UNIMPLEMENTED(anonfs_mkdir, (vnode_t* parent, const char* name))
ANONFS_UNIMPLEMENTED(anonfs_rmdir, (vnode_t* parent, const char* name))
ANONFS_UNIMPLEMENTED(anonfs_read, (vnode_t* vnode, int offset, void* buf, int bufsize))
ANONFS_UNIMPLEMENTED(anonfs_write, (vnode_t* vnode, int offset, const void* buf, int bufsize))
ANONFS_UNIMPLEMENTED(anonfs_link, (vnode_t* parent, vnode_t* vnode, const char* name))
ANONFS_UNIMPLEMENTED(anonfs_unlink, (vnode_t* parent, const char* name))
ANONFS_UNIMPLEMENTED(anonfs_getdents, (vnode_t* vnode, int offset, void* buf, int bufsize))
ANONFS_UNIMPLEMENTED(anonfs_symlink, (vnode_t* parent, const char* name, const char* path))
ANONFS_UNIMPLEMENTED(anonfs_readlink, (vnode_t* node, char* buf, int bufsize))
ANONFS_UNIMPLEMENTED(anonfs_truncate, (vnode_t* node, koff_t length));
ANONFS_UNIMPLEMENTED(anonfs_read_page, (vnode_t* vnode, int page_offset, void* buf))
ANONFS_UNIMPLEMENTED(anonfs_write_page, (vnode_t* vnode, int page_offset, const void* buf))
