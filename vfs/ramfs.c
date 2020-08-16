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

#include <stdbool.h>
#include <stdint.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/ramfs.h"
#include "vfs/fs.h"
#include "vfs/vnode.h"

#define RAMFS_MAX_INODES 1024
#define INVALID_INO ((ino_t)-1)

// TODO(aoates): put this in a common location.
#define MIN(a, b) ({ \
  typeof(a) _a = (a); \
  typeof(b) _b = (b); \
  _a < _b ? _a : _b;})

#define MAX(a, b) ({ \
  typeof(a) _a = (a); \
  typeof(b) _b = (b); \
  _a > _b ? _a : _b;})


// TODO(aoates): just use a different "on-disk" format to make things clearer.
struct ramfs_inode {
  vnode_t vnode;  // We use num, type, and len.
  uint8_t* data;
  int link_count;  // An inode can be deallocated when it's link_count (and vnode refcount) go to zero.
};
typedef struct ramfs_inode ramfs_inode_t;

struct ramfs {
  fs_t fs;  // Embedded fs interface.

  // For each inode number, we just store a ramfs_inode_t directly.  We don't
  // use all the fields of the vnode_t, though.
  ramfs_inode_t inodes[RAMFS_MAX_INODES];

  // Whether or not the appropriate syscalls should block.
  bool enable_blocking;
};
typedef struct ramfs ramfs_t;


// Find and return a free inode number, or -1 on failure.
static int find_free_inode(ramfs_t* ramfs) {
  int inode = -1;
  for (inode = 0; inode < RAMFS_MAX_INODES; ++inode) {
    if (ramfs->inodes[inode].vnode.num == -1) {
      return inode;
    }
  }
  // Out of inodes :(
  return -1;
}

// Initialize the fields for a new "on-disk" inode.
static void init_inode(ramfs_t* ramfs, ramfs_inode_t* node) {
  node->data = kmalloc(1);
  node->link_count = 0;

  vnode_t* vnode = (vnode_t*)node;
  vnode->len = 0;
  kstrcpy(vnode->fstype, "ramfs");
  vnode->fs = (fs_t*)ramfs;
}

// Given an in-memory inode, write its metadata back to "disk".  Call this
// whenever you change things like len, link_count, data ptr, etc.
static void writeback_metadata(vnode_t* vnode) {
  ramfs_inode_t* disk_inode =
      &((ramfs_t*)vnode->fs)->inodes[vnode->num];
  KASSERT(disk_inode->vnode.num == vnode->num);
  KASSERT(disk_inode->vnode.type == vnode->type);
  disk_inode->vnode.len = vnode->len;
  disk_inode->vnode.uid = vnode->uid;
  disk_inode->vnode.gid = vnode->gid;
  disk_inode->vnode.mode = vnode->mode;
}

// Find the dirent in the parent's data with the given name, or NULL.
static dirent_t* find_dirent(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  ramfs_inode_t* inode = &ramfs->inodes[parent->num];

  int offset = 0;
  while (offset < parent->len) {
    dirent_t* d = (dirent_t*)(inode->data + offset);

    if (kstrcmp(d->d_name, name) == 0) {
      KASSERT(d->d_ino != INVALID_INO);
      return d;
    }

    offset += d->d_reclen;
  }

  return 0;
}

// Return the number of entries (including '.' and '..') in a directory.
static int count_dirents(vnode_t* parent) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  ramfs_inode_t* inode = &ramfs->inodes[parent->num];

  int offset = 0, count = 0;
  while (offset < parent->len) {
    dirent_t* d = (dirent_t*)(inode->data + offset);
    if (d->d_ino != INVALID_INO) {
      count++;
    }
    offset += d->d_reclen;
  }

  return count;
}

static int ramfs_link_internal(vnode_t* parent, int inode, const char* name) {
  // TODO(aoates): look for deleted dirent_t slots to reuse.
  dirent_t* d = find_dirent(parent, name);
  if (d) {
    return -EEXIST;
  }

  // This is sorta inefficient....there's really no need to create it on the
  // heap then copy it over, but whatever.
  const int dlen = sizeof(dirent_t) + kstrlen(name) + 1;
  dirent_t* dirent = (dirent_t*)kmalloc(dlen);
  dirent->d_ino = inode;
  dirent->d_reclen = dlen;
  kstrcpy(dirent->d_name, name);

  // Append the new dirent.
  int result = ramfs_write(parent, parent->len, dirent, dlen);
  KASSERT(result == dlen);
  kfree(dirent);

  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  ramfs_inode_t* inode_ptr = &ramfs->inodes[inode];
  inode_ptr->link_count++;
  return 0;
}

static void maybe_block(struct fs* fs) {
  ramfs_t* ramfs = (ramfs_t*)fs;
  if (ramfs->enable_blocking) {
    scheduler_yield();
  }
}

fs_t* ramfs_create_fs(int create_default_dirs) {
  ramfs_t* f = (ramfs_t*)kmalloc(sizeof(ramfs_t));
  kmemset(f, 0, sizeof(ramfs_t));
  vfs_fs_init(&f->fs);

  for (int i = 0; i < RAMFS_MAX_INODES; ++i) {
    f->inodes[i].vnode.num = -1;
  }
  f->enable_blocking = false;

  kstrcpy(f->fs.fstype, "ramfs");
  f->fs.alloc_vnode = &ramfs_alloc_vnode;
  f->fs.get_root = &ramfs_get_root;
  f->fs.get_vnode = &ramfs_get_vnode;
  f->fs.put_vnode = &ramfs_put_vnode;
  f->fs.lookup = &ramfs_lookup;
  f->fs.mknod = &ramfs_mknod;
  f->fs.mkdir = &ramfs_mkdir;
  f->fs.rmdir = &ramfs_rmdir;
  f->fs.read = &ramfs_read;
  f->fs.write = &ramfs_write;
  f->fs.link = &ramfs_link;
  f->fs.unlink = &ramfs_unlink;
  f->fs.getdents = &ramfs_getdents;
  f->fs.stat = &ramfs_stat;
  f->fs.symlink = &ramfs_symlink;
  f->fs.readlink = &ramfs_readlink;
  f->fs.truncate = &ramfs_truncate;
  f->fs.read_page = &ramfs_read_page;
  f->fs.write_page = &ramfs_write_page;

  // Allocate the root inode.
  int root_inode = find_free_inode(f);
  KASSERT(root_inode == 0);
  ramfs_inode_t* root = &f->inodes[root_inode];
  init_inode(f, root);
  root->link_count = 1;
  root->vnode.num = root_inode;
  root->vnode.len = 0;
  root->vnode.type = VNODE_DIRECTORY;
  root->vnode.uid = SUPERUSER_UID;
  root->vnode.gid = SUPERUSER_GID;
  root->vnode.mode =
      VFS_S_IRWXU | VFS_S_IRGRP | VFS_S_IXGRP | VFS_S_IROTH | VFS_S_IXOTH;

  // Link it to itself.
  ramfs_link_internal((vnode_t*)root, root_inode, ".");
  ramfs_link_internal((vnode_t*)root, root_inode, "..");

  if (create_default_dirs) {
    ramfs_mkdir(&root->vnode, "proc");
  }

  return (fs_t*)f;
}

void ramfs_destroy_fs(fs_t* fs) {
  ramfs_t* ramfs = (ramfs_t*)fs;
  KASSERT(ramfs->fs.open_vnodes == 0);
  for (int i = 0; i < RAMFS_MAX_INODES; ++i) {
    if (ramfs->inodes[i].data)
      kfree(ramfs->inodes[i].data);
  }
  kfree(ramfs);
}

void ramfs_enable_blocking(fs_t* fs) {
  KASSERT(kstrcmp(fs->fstype, "ramfs") == 0);
  ramfs_t* ramfs = (ramfs_t*)fs;
  ramfs->enable_blocking = true;
}

void ramfs_disable_blocking(fs_t* fs) {
  KASSERT(kstrcmp(fs->fstype, "ramfs") == 0);
  ramfs_t* ramfs = (ramfs_t*)fs;
  ramfs->enable_blocking = false;
}

vnode_t* ramfs_alloc_vnode(struct fs* fs) {
  vnode_t* node = (vnode_t*)kmalloc(sizeof(vnode_t));
  kmemset(node, 0, sizeof(vnode_t));
  return node;
}

int ramfs_get_root(struct fs* fs) {
  return 0;
}

int ramfs_get_vnode(vnode_t* n) {
  maybe_block(n->fs);

  ramfs_t* ramfs = (ramfs_t*)n->fs;
  if (n->num < 0 || n->num >= RAMFS_MAX_INODES ||
      ramfs->inodes[n->num].vnode.num == -1) {
    return -ENOENT;
  }

  ramfs_inode_t* inode = &ramfs->inodes[n->num];

  // Copy over everything we'll need.
  n->type = inode->vnode.type;
  n->len = inode->vnode.len;
  n->uid = inode->vnode.uid;
  n->gid = inode->vnode.gid;
  n->mode = inode->vnode.mode;
  n->dev = inode->vnode.dev;
  kstrcpy(n->fstype, "ramfs");

  return 0;
}

int ramfs_put_vnode(vnode_t* vnode) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(vnode->refcount == 0);
  maybe_block(vnode->fs);

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* inode = &ramfs->inodes[vnode->num];
  writeback_metadata(vnode);

  if (inode->link_count == 0) {
    vnode->type = VNODE_INVALID;
    kfree(inode->data);
    inode->data = 0x0;
  }
  return 0;
}

int ramfs_lookup(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  maybe_block(parent->fs);
  if (parent->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  dirent_t* d = find_dirent(parent, name);
  if (!d) {
    return -ENOENT;
  }
  return d->d_ino;
}

int ramfs_mknod(vnode_t* parent, const char* name,
                vnode_type_t type, apos_dev_t dev) {
  KASSERT(type == VNODE_REGULAR || type == VNODE_BLOCKDEV ||
          type == VNODE_CHARDEV || type == VNODE_FIFO);
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  maybe_block(parent->fs);

  int new_inode = find_free_inode(ramfs);
  if (new_inode < 0) {
    return -ENOSPC;
  }

  ramfs_inode_t* n = &ramfs->inodes[new_inode];
  KASSERT(n->vnode.num == -1);
  n->vnode.num = new_inode;
  init_inode(ramfs, n);

  n->vnode.type = type;
  n->vnode.dev = dev;
  int result = ramfs_link(parent, (vnode_t*)n, name);
  if (result >= 0) {
    return n->vnode.num;
  } else {
    // TODO(aoates): destroy vnode on error!
    return result;
  }
}

int ramfs_mkdir(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  maybe_block(parent->fs);

  int new_inode = find_free_inode(ramfs);
  if (new_inode < 0) {
    return -ENOSPC;
  }

  ramfs_inode_t* n = &ramfs->inodes[new_inode];
  KASSERT(n->vnode.num == -1);
  n->vnode.num = new_inode;
  init_inode(ramfs, n);

  n->vnode.type = VNODE_DIRECTORY;
  int result = ramfs_link_internal(parent, n->vnode.num, name);
  if (result < 0) {
    // TODO(aoates): destroy vnode on error!
    return result;
  }

  // Create '.' and '..' as well.
  result = ramfs_link_internal((vnode_t*)n, n->vnode.num, ".");
  if (result < 0) {
    // TODO(aoates): destroy vnode on error!
    return result;
  }
  result = ramfs_link_internal((vnode_t*)n, parent->num, "..");
  if (result < 0) {
    // TODO(aoates): destroy vnode on error!
    return result;
  }

  return n->vnode.num;
}

int ramfs_rmdir(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  maybe_block(parent->fs);
  if (parent->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  dirent_t* d = find_dirent(parent, name);
  if (!d) {
    return -ENOENT;
  }

  // Record that it was deleted.
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  KASSERT(d->d_ino != INVALID_INO && d->d_ino < RAMFS_MAX_INODES);
  KASSERT(ramfs->inodes[d->d_ino].vnode.num != -1);
  ramfs_inode_t* dir_inode = &ramfs->inodes[d->d_ino];
  if (dir_inode->vnode.type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  const int dirents = count_dirents(&dir_inode->vnode);
  KASSERT(dirents >= 2);
  if (dirents > 2) {
    return -ENOTEMPTY;
  }

  ramfs_inode_t* parent_inode = &ramfs->inodes[parent->num];
  KASSERT(parent_inode->link_count >= 3);
  parent_inode->link_count--;

  // One each for the parent and '.'.
  // TODO(aoates): if link_count == 0, recollect the inode.
  dir_inode->link_count -= 2;

  // Remove '.' and '..'.
  dirent_t* child_dirent = find_dirent(&dir_inode->vnode, ".");
  child_dirent->d_ino = INVALID_INO;
  child_dirent->d_name[0] = '\0';
  child_dirent = find_dirent(&dir_inode->vnode, "..");
  KASSERT(child_dirent->d_ino == (ino_t)parent->num);
  child_dirent->d_ino = INVALID_INO;
  child_dirent->d_name[0] = '\0';

  d->d_ino = INVALID_INO;
  d->d_name[0] = '\0';
  return 0;
}

int ramfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  int len = MAX(0, MIN(vnode->len - offset, bufsize));
  kmemcpy(buf, node->data + offset, len);
  return len;
}

int ramfs_write(vnode_t* vnode, int offset, const void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  const int newlen = offset + bufsize;

  // Resize buffer if need be.
  if (newlen > vnode->len) {
    uint8_t* newdata = (uint8_t*)kmalloc(newlen);
    KASSERT(newdata);
    kmemcpy(newdata, node->data, vnode->len);
    kmemset(newdata + vnode->len, '\0', newlen - vnode->len);
    kfree(node->data);
    node->data = newdata;
    vnode->len = newlen;

    // Write it back to "disk" as well.
    writeback_metadata(vnode);
  }

  kmemcpy(node->data + offset, buf, bufsize);
  return bufsize;
}

int ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(parent->type == VNODE_DIRECTORY);
  maybe_block(vnode->fs);

  int result = ramfs_link_internal(parent, vnode->num, name);
  if (result) return result;

  if (vnode->type == VNODE_DIRECTORY) {
    dirent_t* d = find_dirent(vnode, "..");
    KASSERT_DBG(d != NULL);
    int orig_dotdot_ino = d->d_ino;
    ramfs_t* ramfs = (ramfs_t*)parent->fs;
    ramfs_inode_t* orig_dotdot_inode = &ramfs->inodes[orig_dotdot_ino];
    orig_dotdot_inode->link_count--;

    d->d_ino = parent->num;
    ramfs_inode_t* new_dotdot_inode = &ramfs->inodes[parent->num];
    new_dotdot_inode->link_count++;
  }

  return 0;
}

// TODO(aoates): a good test: create a file, unlink it, create a new one with
// the same name, do stuff to it and verify it's a totaly new file.
int ramfs_unlink(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  maybe_block(parent->fs);
  if (parent->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  dirent_t* d = find_dirent(parent, name);
  if (!d) {
    return -ENOENT;
  }

  // Record that it was deleted.
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  KASSERT(d->d_ino != INVALID_INO && d->d_ino < RAMFS_MAX_INODES);
  KASSERT(ramfs->inodes[d->d_ino].vnode.num != -1);

  ramfs->inodes[d->d_ino].link_count--;

  d->d_ino = INVALID_INO;
  d->d_name[0] = '\0';
  return 0;
}

int ramfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);
  if (vnode->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];

  // In ramfs, we store dirent_ts directly.
  int bytes_read = 0;  // Our current index into buf.
  while (offset < vnode->len) {
    dirent_t* d = (dirent_t*)(node->data + offset);
    if (d->d_ino != INVALID_INO &&
        bytes_read + d->d_reclen >= (size_t)bufsize) {
      // If the buffer is too small to fit even one entry, return -EINVAL.
      if (bytes_read == 0) {
        return -EINVAL;
      }
      break;
    }
    offset += d->d_reclen;
    d->d_offset = offset;

    // Skip dirents that have been unlinked.
    if (d->d_ino == INVALID_INO) {
      continue;
    }
    kmemcpy(buf + bytes_read, d, d->d_reclen);
    bytes_read += d->d_reclen;
  }

  return bytes_read;
}

int ramfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  stat_out->st_nlink = node->link_count;
  stat_out->st_blksize = 512;
  stat_out->st_blocks = ceiling_div(vnode->len, 512);
  return 0;
}

int ramfs_symlink(vnode_t* parent, const char* name, const char* path) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  ramfs_t* ramfs = (ramfs_t*)parent->fs;
  maybe_block(parent->fs);

  int new_inode = find_free_inode(ramfs);
  if (new_inode < 0) {
    return -ENOSPC;
  }

  ramfs_inode_t* n = &ramfs->inodes[new_inode];
  KASSERT(n->vnode.num == -1);
  n->vnode.num = new_inode;
  init_inode(ramfs, n);

  n->vnode.type = VNODE_SYMLINK;
  n->vnode.mode = VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO;
  int result = ramfs_write(&n->vnode, 0, path, kstrlen(path));
  if (result < 0) return result;

  result = ramfs_link(parent, (vnode_t*)n, name);
  if (result >= 0) {
    return 0;
  } else {
    // TODO(aoates): destroy vnode on error!
    return result;
  }
}

int ramfs_readlink(vnode_t* node, char* buf, int bufsize) {
  return ramfs_read(node, 0, buf, bufsize);
}

int ramfs_truncate(vnode_t* vnode, off_t length) {
  KASSERT_DBG(vnode->type == VNODE_REGULAR);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  if (vnode->len == length) return 0;

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  uint8_t* newdata = (uint8_t*)kmalloc(length);
  KASSERT(newdata);
  kmemcpy(newdata, node->data, min(length, vnode->len));
  if (length > vnode->len) {
    kmemset(newdata + vnode->len, '\0', length - vnode->len);
  }

  kfree(node->data);
  node->data = newdata;
  vnode->len = length;

  // Write it back to "disk" as well.
  writeback_metadata(vnode);
  return 0;
}

int ramfs_read_page(vnode_t* vnode, int page_offset, void* buf) {
  KASSERT((addr_t)buf % PAGE_SIZE == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);
  if (vnode->type != VNODE_REGULAR) {
    return -EISDIR;
  }

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  int len = MAX(0, MIN(vnode->len - (page_offset * PAGE_SIZE), PAGE_SIZE));
  kmemcpy(buf, node->data + (page_offset * PAGE_SIZE), len);
  return 0;
}

int ramfs_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  KASSERT((addr_t)buf % PAGE_SIZE == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);
  if (vnode->type != VNODE_REGULAR) {
    return -EISDIR;
  }

  ramfs_t* ramfs = (ramfs_t*)vnode->fs;
  ramfs_inode_t* node = &ramfs->inodes[vnode->num];
  int len = MAX(0, MIN(vnode->len - (page_offset * PAGE_SIZE), PAGE_SIZE));
  kmemcpy(node->data + (page_offset * PAGE_SIZE), buf, len);
  return 0;
}
