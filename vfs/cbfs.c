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

#include "vfs/cbfs.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "proc/user.h"
#include "vfs/vfs.h"

#define CBFS_ROOT_INO 0

typedef struct {
  int num;
  char name[VFS_MAX_FILENAME_LENGTH];
  cbfs_read_t read_cb;
  void* arg;

  uid_t uid;
  gid_t gid;
  mode_t mode;

  list_link_t link;
} cbfs_entry_t;

typedef struct {
  fs_t fs;

  uid_t root_uid;
  gid_t root_gid;
  mode_t root_mode;
  int next_ino;

  list_t root;
} cbfs_t;

static inline cbfs_t* fs_to_cbfs(fs_t* f) {
  return (cbfs_t*)f;
}

static cbfs_entry_t* lookup(cbfs_t* cfs, int num) {
  list_link_t* n = cfs->root.head;
  while (n) {
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (entry->num == num) return entry;
    n = n->next;
  }

  return 0x0;
}

static cbfs_entry_t* lookup_by_name(cbfs_t* cfs, const char* name) {
  list_link_t* n = cfs->root.head;
  while (n) {
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (kstrcmp(name, entry->name) == 0) return entry;
    n = n->next;
  }
  return 0x0;
}

static vnode_t* cbfs_alloc_vnode(struct fs* fs);
static int cbfs_get_root(struct fs* fs);
static int cbfs_get_vnode(vnode_t* vnode);
static int cbfs_put_vnode(vnode_t* vnode);
static int cbfs_lookup(vnode_t* parent, const char* name);
static int cbfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev);
static int cbfs_mkdir(vnode_t* parent, const char* name);
static int cbfs_rmdir(vnode_t* parent, const char* name);
static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize);
static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int cbfs_unlink(vnode_t* parent, const char* name);
static int cbfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf);
static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

fs_t* cbfs_create(void) {
  cbfs_t* f = (cbfs_t*)kmalloc(sizeof(cbfs_t));
  vfs_fs_init(&f->fs);

  kstrcpy(f->fs.fstype, "cbfs");
  f->fs.alloc_vnode = &cbfs_alloc_vnode;
  f->fs.get_root = &cbfs_get_root;
  f->fs.get_vnode = &cbfs_get_vnode;
  f->fs.put_vnode = &cbfs_put_vnode;
  f->fs.lookup = &cbfs_lookup;
  f->fs.mknod = &cbfs_mknod;
  f->fs.mkdir = &cbfs_mkdir;
  f->fs.rmdir = &cbfs_rmdir;
  f->fs.read = &cbfs_read;
  f->fs.write = &cbfs_write;
  f->fs.link = &cbfs_link;
  f->fs.unlink = &cbfs_unlink;
  f->fs.getdents = &cbfs_getdents;
  f->fs.stat = &cbfs_stat;
  f->fs.read_page = &cbfs_read_page;
  f->fs.write_page = &cbfs_write_page;

  f->next_ino = 1;
  f->root = LIST_INIT;
  f->root_uid = SUPERUSER_UID;
  f->root_gid = SUPERUSER_GID;
  f->root_mode = VFS_S_IRUSR | VFS_S_IXUSR | VFS_S_IRGRP | VFS_S_IXGRP |
      VFS_S_IROTH | VFS_S_IXOTH;

  // Create '.' and '..'
  const char* const kNames[] = {".", ".."};
  for (int i = 0; i < 2; ++i) {
    cbfs_entry_t* entry = (cbfs_entry_t*)kmalloc(sizeof(cbfs_entry_t));
    kstrcpy(entry->name, kNames[i]);
    entry->num = CBFS_ROOT_INO;
    entry->read_cb = 0x0;
    entry->arg = 0x0;
    entry->mode = f->root_mode;
    entry->uid = f->root_uid;
    entry->gid = f->root_gid;
    entry->link = LIST_LINK_INIT;

    list_push(&f->root, &entry->link);
  }

  return &f->fs;
}

void cbfs_free(fs_t* fs) {
  kfree(fs_to_cbfs(fs));
}

int cbfs_create_file(fs_t* fs, const char* name,
                     cbfs_read_t read_cb, void* arg, mode_t mode) {
  cbfs_t* cfs = fs_to_cbfs(fs);
  if (lookup_by_name(cfs, name) != 0x0) return -EEXIST;

  cbfs_entry_t* entry = (cbfs_entry_t*)kmalloc(sizeof(cbfs_entry_t));
  kstrcpy(entry->name, name);
  entry->num = cfs->next_ino++;
  entry->read_cb = read_cb;
  entry->arg = arg;
  entry->mode = mode;
  entry->uid = proc_current()->euid;
  entry->gid = proc_current()->egid;
  entry->link = LIST_LINK_INIT;

  list_push(&cfs->root, &entry->link);

  return 0;
}

static vnode_t* cbfs_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int cbfs_get_root(struct fs* fs) {
  return CBFS_ROOT_INO;
}

static int cbfs_get_vnode(vnode_t* vnode) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  if (vnode->num == CBFS_ROOT_INO) {
    vnode->type = VNODE_DIRECTORY;
    vnode->uid = cfs->root_uid;
    vnode->gid = cfs->root_gid;
    vnode->mode = cfs->root_mode;
    kstrcpy(vnode->fstype, "cbfs");
    return 0;
  }

  cbfs_entry_t* entry = lookup(cfs, vnode->num);
  if (!entry) return -ENOENT;

  vnode->type = VNODE_REGULAR;
  vnode->uid = entry->uid;
  vnode->gid = entry->gid;
  vnode->mode = entry->mode;
  kstrcpy(vnode->fstype, "cbfs");
  return 0;
}

static int cbfs_put_vnode(vnode_t* vnode) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  if (vnode->num == CBFS_ROOT_INO) {
    cfs->root_uid = vnode->uid;
    cfs->root_gid = vnode->gid;
    cfs->root_mode = vnode->mode;
    return 0;
  }

  cbfs_entry_t* entry = lookup(cfs, vnode->num);
  if (!entry) return -ENOENT;

  entry->uid = vnode->uid;
  entry->gid = vnode->gid;
  entry->mode = vnode->mode;

  return 0;
}

static int cbfs_lookup(vnode_t* parent, const char* name) {
  KASSERT(parent->num == CBFS_ROOT_INO);

  cbfs_t* cfs = fs_to_cbfs(parent->fs);
  cbfs_entry_t* entry = lookup_by_name(cfs, name);
  if (entry) return entry->num;
  else return -ENOENT;
}

static int cbfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int cbfs_mkdir(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int cbfs_rmdir(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  if (offset > 0) return 0;

  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_entry_t* entry = lookup(cfs, vnode->num);

  return entry->read_cb(vnode->fs, entry->arg, offset, buf, bufsize);
}

static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize) {
  return -EACCES;
}

static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int cbfs_unlink(vnode_t* parent, const char* name) {
  KASSERT(parent->num == 0);
  return -EACCES;
}

static int cbfs_getdents(vnode_t* vnode, int offset, void* outbuf,
                           int outbufsize) {
  KASSERT(vnode->num == 0);

  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  list_link_t* n = cfs->root.head;
  int idx = 0;
  while (n && idx < offset) {
    n = n->next;
    idx++;
  }

  if (!n) return 0;

  int bytes_written = 0;
  while (1) {
    if (!n) break;
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);

    const int dirent_len = sizeof(dirent_t) + kstrlen(entry->name) + 1;
    if (bytes_written + dirent_len > outbufsize) break;

    dirent_t* d = (dirent_t*)(((const char*)outbuf) + bytes_written);
    d->vnode = entry->num;
    d->offset = idx + 1;
    d->length = dirent_len;
    kstrcpy(d->name, entry->name);

    bytes_written += dirent_len;
    n = n->next;
    idx++;
  }
  return bytes_written;
}

static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  KASSERT(vnode->num == 0);
  stat_out->st_mode = VFS_S_IFDIR | VFS_S_IRUSR | VFS_S_IXUSR;
  stat_out->st_nlink = 2;
  stat_out->st_rdev = mkdev(0, 0);
  stat_out->st_size = 2 * sizeof(dirent_t) + 5;
  stat_out->st_blksize = 512;
  stat_out->st_blocks = 1;
  return 0;
}

static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf) {
  return -ENOTSUP;
}

static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  return -ENOTSUP;
}
