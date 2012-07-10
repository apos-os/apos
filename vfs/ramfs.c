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

struct ramfs {
  fs_t fs;  // Embedded fs interface.

  // For each inode number, a pointer to its vnode.
  vnode_t* inodes[RAMFS_MAX_INODES];
};
typedef struct ramfs ramfs_t;

struct ramfs_inode {
  vnode_t vnode;
  uint8_t* data;

  // TODO(aoates): link count
};
typedef struct ramfs_inode ramfs_inode_t;

fs_t* ramfs_create() {
  ramfs_t* f = (ramfs_t*)kmalloc(sizeof(ramfs_t));

  for (int i = 0; i < RAMFS_MAX_INODES; ++i) {
    f->inodes[i] = 0x0;
  }

  f->fs.alloc_vnode = &ramfs_alloc_vnode;
  f->fs.get_vnode = &ramfs_get_vnode;
  f->fs.read = &ramfs_read;
  f->fs.write = &ramfs_write;
  f->fs.link = &ramfs_link;
  f->fs.getdents = &ramfs_getdents;

  f->fs.root = ramfs_alloc_vnode((fs_t*)f);
  f->fs.root->type = VNODE_DIRECTORY;

  return (fs_t*)f;
}

vnode_t* ramfs_alloc_vnode(fs_t* f) {
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

  vnode_t* vnode = (vnode_t*)node;
  vfs_vnode_init(vnode);
  vnode->num = inode;
  vnode->len = 0;
  kstrcpy(vnode->fstype, "ramfs");
  vnode->fs = f;

  ramfs->inodes[inode] = vnode;

  return vnode;
}

vnode_t* ramfs_get_vnode(fs_t* fs, int vnode) {
  KASSERT(vnode >= 0 && vnode < RAMFS_MAX_INODES);
  ramfs_t* ramfs = (ramfs_t*)fs;
  return ramfs->inodes[vnode];
}

int ramfs_read(vnode_t* vnode, int offset, uint8_t* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);

  ramfs_inode_t* node = (ramfs_inode_t*)vnode;
  int len = MIN(vnode->len - offset, bufsize);
  kmemcpy(buf, node->data + offset, len);
  return len;
}

int ramfs_write(vnode_t* vnode, int offset, const uint8_t* buf, int bufsize) {
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

void ramfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  KASSERT(kstrcmp(parent->fstype, "ramfs") == 0);
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(parent->type == VNODE_DIRECTORY);

  // This is sorta inefficient....there's really no need to create it on the
  // heap then copy it over, but whatever.
  const int dlen = sizeof(dirent_t) + kstrlen(name) + 1;
  dirent_t* dirent = (dirent_t*)kmalloc(dlen);
  dirent->vnode = vnode->num;
  dirent->length = dlen;
  kstrcpy(dirent->name, name);

  // Append the new dirent.
  int result = ramfs_write(parent, parent->len, (uint8_t*)dirent, dlen);
  KASSERT(result == dlen);
}

int ramfs_getdents(vnode_t* vnode, int offset, uint8_t* buf, int bufsize) {
  KASSERT(kstrcmp(vnode->fstype, "ramfs") == 0);
  KASSERT(vnode->type == VNODE_DIRECTORY);
  ramfs_inode_t* node = (ramfs_inode_t*)vnode;

  // In ramfs, we store dirent_ts directly.
  int bytes_read = 0;
  while (offset < vnode->len) {
    dirent_t* d = (dirent_t*)(node->data + offset);
    if (bytes_read + d->length >= bufsize) {
      break;
    }

    kmemcpy(buf, d, d->length);
    bytes_read += d->length;
    offset += d->length;
  }

  return bytes_read;
}
