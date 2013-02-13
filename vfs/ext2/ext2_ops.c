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

#include "vfs/ext2/ext2_ops.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/block_cache.h"
#include "kmalloc.h"
#include "vfs/vfs.h"

#include "vfs/ext2/ext2-internal.h"
#include "vfs/ext2/ext2fs.h"

static vnode_t* ext2_alloc_vnode(struct fs* fs);
static int ext2_get_root(struct fs* fs);
static int ext2_get_vnode(vnode_t* vnode);
static int ext2_put_vnode(vnode_t* vnode);
static int ext2_lookup(vnode_t* parent, const char* name);
static int ext2_create(vnode_t* parent, const char* name);
static int ext2_mkdir(vnode_t* parent, const char* name);
static int ext2_rmdir(vnode_t* parent, const char* name);
static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int ext2_write(vnode_t* vnode, int offset, const void* buf, int bufsize);
static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int ext2_unlink(vnode_t* parent, const char* name);
static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);

// Given a block-sized bitmap (i.e. a block group's block or inode bitmap),
// return the value of the Nth entry.
static inline int bg_bitmap_get(ext2fs_t* fs, void* bitmap, int n) {
  KASSERT_DBG(n >= 0);
  return (((uint8_t*)bitmap)[n / 8] >> (n % 8)) & 0x01;
}

// Given an inode number (1-indexed), find the corresponding inode on disk and
// fill the given ext2_inode_t.  Returns 0 on success, or -errno on error.
static int get_inode(ext2fs_t* fs, uint32_t inode_num, ext2_inode_t* inode) {
  if (inode_num <= 0) {
    return -ERANGE;
  }
  if (inode_num > fs->sb.s_inodes_count) {
    return -ENOENT;
  }

  // Find the block group and load it's inode bitmap.
  const uint32_t bg = (inode_num - 1) / fs->sb.s_inodes_per_group;
  const uint32_t bg_inode_idx = (inode_num - 1) % fs->sb.s_inodes_per_group;
  KASSERT(bg < fs->num_block_groups);
  const uint32_t bg_inode_bitmap_block = fs->block_groups[bg].bg_inode_bitmap;
  void* bg_inode_bitmap = block_cache_get(fs->dev, bg_inode_bitmap_block);
  if (!bg_inode_bitmap) {
    klogf("ext2: warning: couldn't get inode bitmap for block "
          "group %d (block %d)\n", bg, bg_inode_bitmap_block);
    return -ENOENT;
  }
  if (!bg_bitmap_get(fs, bg_inode_bitmap, bg_inode_idx)) {
    block_cache_put(fs->dev, bg_inode_bitmap_block);
    return -ENOENT;
  }
  block_cache_put(fs->dev, bg_inode_bitmap_block);

  // We know that the inode is allocated, now get it from the inode table.
  // The inode table map span multiple blocks, so figure out which block we
  // need.
  const uint32_t block_size = ext2_block_size(fs);
  KASSERT(block_size % fs->sb.s_inode_size == 0);
  const uint32_t bg_inode_table_block_offset =
      (bg_inode_idx * fs->sb.s_inode_size) / block_size;
  const uint32_t bg_inode_table_block =
      fs->block_groups[bg].bg_inode_table + bg_inode_table_block_offset;
  void* bg_inode_table = block_cache_get(fs->dev, bg_inode_table_block);
  if (!bg_inode_table) {
    klogf("ext2: warning: couldn't get inode table for block "
          "group %d (block %d)\n", bg, bg_inode_table_block);
    return -ENOENT;
  }

  ext2_inode_t* disk_inode = (ext2_inode_t*)(
      bg_inode_table + (bg_inode_idx * fs->sb.s_inode_size) -
      (block_size * bg_inode_table_block_offset));
  kmemcpy(inode, disk_inode, fs->sb.s_inode_size);
  block_cache_put(fs->dev, bg_inode_table_block);

  ext2_inode_ltoh(inode);
  return 0;
}

void ext2_set_ops(fs_t* fs) {
  fs->alloc_vnode = &ext2_alloc_vnode;
  fs->get_root = &ext2_get_root;
  fs->get_vnode = &ext2_get_vnode;
  fs->put_vnode = &ext2_put_vnode;
  fs->lookup = &ext2_lookup;
  fs->create = &ext2_create;
  fs->mkdir = &ext2_mkdir;
  fs->rmdir = &ext2_rmdir;
  fs->read = &ext2_read;
  fs->write = &ext2_write;
  fs->link = &ext2_link;
  fs->unlink = &ext2_unlink;
  fs->getdents = &ext2_getdents;
}

static vnode_t* ext2_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int ext2_get_root(struct fs* fs) {
  return EXT2_ROOT_INO;
}

static int ext2_get_vnode(vnode_t* vnode) {
  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  kstrcpy(vnode->fstype, "ext2");
  // Fill in the vnode_t with data from the filesystem.  The vnode_t will have
  // been allocated with alloc_vnode and had the following fields initalized:
  // num, refcount, fs, mutex.  The FS should initialize the remaining fields
  // (and any FS-specific fields), and return 0 on success, or -errno on
  // failure.
  ext2_inode_t* inode = (ext2_inode_t*)kmalloc(fs->sb.s_inode_size);
  int result = get_inode(fs, vnode->num, inode);
  if (result) {
    kfree(inode);
    return result;
  }

  if (inode->i_mode & EXT2_S_IFREG) {
    vnode->type = VNODE_REGULAR;
    // Don't support large files.
    KASSERT(inode->i_dir_acl == 0);
  } else if (inode->i_mode & EXT2_S_IFDIR) {
    vnode->type = VNODE_DIRECTORY;
  } else {
    kfree(inode);
    klogf("ext2: unsupported inode type: 0x%x\n", inode->i_mode);
    return -ENOTSUP;
  }
  vnode->len = inode->i_size;
  kfree(inode);
  return 0;
}

static int ext2_put_vnode(vnode_t* vnode) {
  return -ENOTSUP;
}

static int ext2_lookup(vnode_t* parent, const char* name) {
  return -ENOTSUP;
}

static int ext2_create(vnode_t* parent, const char* name) {
  return -ENOTSUP;
}

static int ext2_mkdir(vnode_t* parent, const char* name) {
  return -ENOTSUP;
}

static int ext2_rmdir(vnode_t* parent, const char* name) {
  return -ENOTSUP;
}

static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  return -ENOTSUP;
}

static int ext2_write(vnode_t* vnode, int offset,
                      const void* buf, int bufsize) {
  return -ENOTSUP;
}

static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  return -ENOTSUP;
}

static int ext2_unlink(vnode_t* parent, const char* name) {
  return -ENOTSUP;
}

static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  return -ENOTSUP;
}

