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

struct ramfs {
  fs_t fs;  // Embedded fs interface.

  // For each inode number, a pointer to its vnode.
  vnode_t* inodes[RAMFS_MAX_INODES];
};
typedef struct ramfs ramfs_t;

struct ramfs_inode {
  vnode_t vnode;
  uint8_t* data;
  uint32_t link_count;  // An inode can be deallocated when it's link_count (and vnode refcount) go to zero.
};
typedef struct ramfs_inode ramfs_inode_t;

static vnode_t* ramfs_alloc_vnode(fs_t* f) {
  ramfs_t* ramfs = (ramfs_t*)f;

  // Find a free inode number.
  int inode = -1;
  for (inode = 0; inode < RAMFS_MAX_INODES; ++inode) {
    if (ramfs->inodes[inode] == 0x0) {
      break;
    }
  }
  KASSERT(inode >= 0);
  if (inode >= RAMFS_MAX_INODES) {
    // Out of inodes :(
    return 0x0;
  }

  ramfs_inode_t* node = (ramfs_inode_t*)kmalloc(sizeof(ramfs_inode_t));
  node->data = kmalloc(1);
  node->link_count = 0;

  vnode_t* vnode = (vnode_t*)node;
  vfs_vnode_init(vnode);
  vnode->num = inode;
  vnode->len = 0;
  kstrcpy(vnode->fstype, "ramfs");
  vnode->fs = f;

  ramfs->inodes[inode] = vnode;

  return vnode;
}

// Find the dirent in the parent's data with the given name, or NULL.
static dirent_t* find_dirent(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  ramfs_inode_t* inode = (ramfs_inode_t*)parent;

  int offset = 0;
  while (offset < parent->len) {
    dirent_t* d = (dirent_t*)(inode->data + offset);

    if (kstrcmp(d->name, name) == 0) {
      return d;
    }

    offset += d->length;
  }

  return 0;
}

fs_t* ramfs_create_fs() {
  ramfs_t* f = (ramfs_t*)kmalloc(sizeof(ramfs_t));
  kmemset(f, 0, sizeof(ramfs_t));

  for (int i = 0; i < RAMFS_MAX_INODES; ++i) {
    f->inodes[i] = 0x0;
  }

  f->fs.get_vnode = &ramfs_get_vnode;
  f->fs.put_vnode = &ramfs_put_vnode;
  f->fs.lookup = &ramfs_lookup;
  f->fs.create = &ramfs_create;
  f->fs.mkdir = &ramfs_mkdir;
  f->fs.read = &ramfs_read;
  f->fs.write = &ramfs_write;
  f->fs.link = &ramfs_link;
  f->fs.unlink = &ramfs_unlink;
  f->fs.getdents = &ramfs_getdents;

  f->fs.root = ramfs_alloc_vnode((fs_t*)f);
  f->fs.root->type = VNODE_DIRECTORY;

  return (fs_t*)f;
}

vnode_t* ramfs_get_vnode(fs_t* fs, int vnode) {
  KASSERT(vnode >= 0 && vnode < RAMFS_MAX_INODES);
  ramfs_t* ramfs = (ramfs_t*)fs;

  vnode_t* n = ramfs->inodes[vnode];
  // No-one else should be referencing this node right now (otherwise, the VFS
  // shouldn't have called this function, if it already had a reference around).
  // KASSERT(n->refcount == 0);
  n->refcount++;
  return n;
}

void ramfs_put_vnode(vnode_t* vnode) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(vnode->refcount == 0);

  ramfs_inode_t* inode = (ramfs_inode_t*)vnode;
  if (inode->link_count == 0) {
    vnode->type = VNODE_INVALID;
    kfree(inode->data);
    inode->data = 0x0;
    kfree(inode);
  }
}

int ramfs_lookup(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
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

  vnode_t* n = ramfs_alloc_vnode(parent->fs);
  n->type = VNODE_REGULAR;
  int result = ramfs_link(parent, n, name);
  if (result >= 0) {
    return n->num;
  } else {
    // TODO(aoates): destroy vnode on error!
    return result;
  }
}

int ramfs_mkdir(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);

  vnode_t* n = ramfs_alloc_vnode(parent->fs);
  n->type = VNODE_DIRECTORY;
  int result = ramfs_link(parent, n, name);
  if (result >= 0) {
    return n->num;
  } else {
    // TODO(aoates): destroy vnode on error!
    return result;
  }
}

int ramfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);

  ramfs_inode_t* node = (ramfs_inode_t*)vnode;
  int len = MAX(0, MIN(vnode->len - offset, bufsize));
  kmemcpy(buf, node->data + offset, len);
  return len;
}

int ramfs_write(vnode_t* vnode, int offset, const void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);

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
  }

  kmemcpy(node->data + offset, buf, bufsize);
  return bufsize;
}

int ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(parent->type == VNODE_DIRECTORY);

  // TODO(aoates): look for deleted dirent_t slots to reuse.
  dirent_t* d = find_dirent(parent, name);
  if (d) {
    return -EEXIST;
  }

  // This is sorta inefficient....there's really no need to create it on the
  // heap then copy it over, but whatever.
  const int dlen = sizeof(dirent_t) + kstrlen(name) + 1;
  dirent_t* dirent = (dirent_t*)kmalloc(dlen);
  dirent->vnode = vnode->num;
  dirent->length = dlen;
  kstrcpy(dirent->name, name);

  // Append the new dirent.
  int result = ramfs_write(parent, parent->len, dirent, dlen);
  KASSERT(result == dlen);

  ramfs_inode_t* inode = (ramfs_inode_t*)vnode;
  inode->link_count++;
  return 0;
}

// TODO(aoates): a good test: create a file, unlink it, create a new one with
// the same name, do stuff to it and verify it's a totaly new file.
int ramfs_unlink(vnode_t* parent, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  if (parent->type != VNODE_DIRECTORY) {
    return -ENOTDIR;
  }

  dirent_t* d = find_dirent(parent, name);
  if (!d) {
    return -ENOENT;
  }

  vnode_t* n = ramfs_get_vnode(parent->fs, d->vnode);
  KASSERT(n != 0x0);

  // Record that it was deleted.
  d->vnode = -1;
  d->name[0] = '\0';
  ((ramfs_inode_t*)n)->link_count--;
  return 0;
}

int ramfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
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
