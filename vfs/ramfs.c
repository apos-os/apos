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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "kmalloc.h"
#include "proc/scheduler.h"
#include "vfs/dirent.h"
#include "vfs/ramfs.h"
#include "vfs/vfs.h"

#define RAMFS_MAX_INODES 1024

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
  uint32_t link_count;  // An inode can be deallocated when it's link_count (and vnode refcount) go to zero.
};
typedef struct ramfs_inode ramfs_inode_t;

struct ramfs {
  fs_t fs;  // Embedded fs interface.

  // For each inode number, we just store a ramfs_inode_t directly.  We don't
  // use all the fields of the vnode_t, though.
  ramfs_inode_t inodes[RAMFS_MAX_INODES];

  // Whether or not the appropriate syscalls should block.
  int enable_blocking;
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
static void writeback_metadata(ramfs_inode_t* inode) {
  ramfs_inode_t* disk_inode =
      &((ramfs_t*)inode->vnode.fs)->inodes[inode->vnode.num];
  KASSERT(disk_inode->vnode.num == inode->vnode.num);
  KASSERT(disk_inode->vnode.type == inode->vnode.type);
  disk_inode->vnode.len = inode->vnode.len;
  disk_inode->data = inode->data;
  disk_inode->link_count = inode->link_count;
}

// Find the dirent in the parent's data with the given name, or NULL.
static dirent_t* find_dirent(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  ramfs_inode_t* inode = (ramfs_inode_t*)parent;

  int offset = 0;
  while (offset < parent->len) {
    dirent_t* d = (dirent_t*)(inode->data + offset);

    if (kstrcmp(d->name, name) == 0) {
      KASSERT(d->vnode >= 0);
      return d;
    }

    offset += d->length;
  }

  return 0;
}

// Return the number of entries (including '.' and '..') in a directory.
static int count_dirents(vnode_t* parent) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  ramfs_inode_t* inode = (ramfs_inode_t*)parent;

  int offset = 0, count = 0;
  while (offset < parent->len) {
    dirent_t* d = (dirent_t*)(inode->data + offset);
    if (d->vnode >= 0) {
      count++;
    }
    offset += d->length;
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
  dirent->vnode = inode;
  dirent->length = dlen;
  kstrcpy(dirent->name, name);

  // Append the new dirent.
  int result = ramfs_write(parent, parent->len, dirent, dlen);
  KASSERT(result == dlen);

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

fs_t* ramfs_create_fs() {
  ramfs_t* f = (ramfs_t*)kmalloc(sizeof(ramfs_t));
  kmemset(f, 0, sizeof(ramfs_t));

  for (int i = 0; i < RAMFS_MAX_INODES; ++i) {
    f->inodes[i].vnode.num = -1;
  }
  f->enable_blocking = 0;

  f->fs.alloc_vnode = &ramfs_alloc_vnode;
  f->fs.get_root = &ramfs_get_root;
  f->fs.get_vnode = &ramfs_get_vnode;
  f->fs.put_vnode = &ramfs_put_vnode;
  f->fs.lookup = &ramfs_lookup;
  f->fs.create = &ramfs_create;
  f->fs.mkdir = &ramfs_mkdir;
  f->fs.rmdir = &ramfs_rmdir;
  f->fs.read = &ramfs_read;
  f->fs.write = &ramfs_write;
  f->fs.link = &ramfs_link;
  f->fs.unlink = &ramfs_unlink;
  f->fs.getdents = &ramfs_getdents;

  // Allocate the root inode.
  int root_inode = find_free_inode(f);
  KASSERT(root_inode == 0);
  ramfs_inode_t* root = &f->inodes[root_inode];
  init_inode(f, root);
  root->link_count = 1;
  root->vnode.num = root_inode;
  root->vnode.len = 0;
  root->vnode.type = VNODE_DIRECTORY;

  // Link it to itself.
  ramfs_link_internal((vnode_t*)root, root_inode, ".");
  ramfs_link_internal((vnode_t*)root, root_inode, "..");

  return (fs_t*)f;
}

void ramfs_enable_blocking(fs_t* fs) {
  ramfs_t* ramfs = (ramfs_t*)fs;
  ramfs->enable_blocking = 1;
}

void ramfs_disable_blocking(fs_t* fs) {
  ramfs_t* ramfs = (ramfs_t*)fs;
  ramfs->enable_blocking = 0;
}

vnode_t* ramfs_alloc_vnode(struct fs* fs) {
  ramfs_inode_t* node = (ramfs_inode_t*)kmalloc(sizeof(ramfs_inode_t));
  kmemset(node, 0, sizeof(ramfs_inode_t));
  return (vnode_t*)node;
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
  kstrcpy(n->fstype, "ramfs");
  ((ramfs_inode_t*)n)->data = inode->data;
  ((ramfs_inode_t*)n)->link_count = inode->link_count;

  return 0;
}

int ramfs_put_vnode(vnode_t* vnode) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(vnode->refcount == 0);
  maybe_block(vnode->fs);

  // TODO(aoates): consider that directories must be treated differently.  Does
  // that mean that the self-linking of directories should go in ramfs, not vfs?
  // Probably.
  ramfs_inode_t* inode = (ramfs_inode_t*)vnode;
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
  return d->vnode;
}

int ramfs_create(vnode_t* parent, const char* name) {
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

  n->vnode.type = VNODE_REGULAR;
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
  KASSERT(d->vnode >= 0 && d->vnode < RAMFS_MAX_INODES);
  KASSERT(ramfs->inodes[d->vnode].vnode.num != -1);
  vnode_t* dir_vnode = (vnode_t*)&ramfs->inodes[d->vnode];
  if (dir_vnode->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  const int dirents = count_dirents(dir_vnode);
  KASSERT(dirents >= 2);
  if (dirents > 2) {
    return -ENOTEMPTY;
  }

  // One each for the parent and '.'.
  // TODO(aoates): if link_count == 0, recollect the inode.
  ((ramfs_inode_t*)dir_vnode)->link_count -= 2;

  d->vnode = -1;
  d->name[0] = '\0';
  return 0;
}

int ramfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  ramfs_inode_t* node = (ramfs_inode_t*)vnode;
  int len = MAX(0, MIN(vnode->len - offset, bufsize));
  kmemcpy(buf, node->data + offset, len);
  return len;
}

int ramfs_write(vnode_t* vnode, int offset, const void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);

  ramfs_inode_t* node = (ramfs_inode_t*)vnode;
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
    writeback_metadata(node);
  }

  kmemcpy(node->data + offset, buf, bufsize);
  return bufsize;
}

int ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT(vnode->type != VNODE_DIRECTORY);
  maybe_block(vnode->fs);

  return ramfs_link_internal(parent, vnode->num, name);
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
  KASSERT(d->vnode >= 0 && d->vnode < RAMFS_MAX_INODES);
  KASSERT(ramfs->inodes[d->vnode].vnode.num != -1);
  if (ramfs->inodes[d->vnode].vnode.type == VNODE_DIRECTORY) {
    return -EISDIR;
  }

  // TODO(aoates): how do we propagate this back to all the vnode_t*s floating
  // around pointing to this inode?
  ramfs->inodes[d->vnode].link_count--;

  d->vnode = -1;
  d->name[0] = '\0';
  return 0;
}

int ramfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  maybe_block(vnode->fs);
  if (vnode->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  ramfs_inode_t* node = (ramfs_inode_t*)vnode;

  // In ramfs, we store dirent_ts directly.
  int bytes_read = 0;  // Our current index into buf.
  while (offset < vnode->len) {
    dirent_t* d = (dirent_t*)(node->data + offset);
    if (bytes_read + d->length >= bufsize) {
      break;
    }
    offset += d->length;
    d->offset = offset;

    // Skip dirents that have been unlinked.
    if (d->vnode == -1) {
      continue;
    }
    kmemcpy(buf + bytes_read, d, d->length);
    bytes_read += d->length;
  }

  return bytes_read;
}
