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

#include "vfs/ext2/ext2-internal.h"

#include "common/endian.h"
#include "common/klog.h"
#include "common/kstring.h"

void ext2_superblock_log(ext2_superblock_t* sb) {
  klogf("s_inodes_count: %u\n", sb->s_inodes_count);
  klogf("s_blocks_count: %u\n", sb->s_blocks_count);
  klogf("s_r_blocks_count: %u\n", sb->s_r_blocks_count);
  klogf("s_free_blocks_count: %u\n", sb->s_free_blocks_count);
  klogf("s_free_inodes_count: %u\n", sb->s_free_inodes_count);
  klogf("s_first_data_block: %u\n", sb->s_first_data_block);
  klogf("s_log_block_size: %u\n", sb->s_log_block_size);
  klogf("s_log_frag_size: %u\n", sb->s_log_frag_size);
  klogf("s_blocks_per_group: %u\n", sb->s_blocks_per_group);
  klogf("s_frags_per_group: %u\n", sb->s_frags_per_group);
  klogf("s_inodes_per_group: %u\n", sb->s_inodes_per_group);
  klogf("s_mtime: %u\n", sb->s_mtime);
  klogf("s_wtime: %u\n", sb->s_wtime);
  klogf("s_mnt_count: %u\n", (uint32_t)sb->s_mnt_count);
  klogf("s_max_mnt_count: %u\n", (uint32_t)sb->s_max_mnt_count);
  klogf("s_magic: 0x%x\n", (uint32_t)sb->s_magic);
  klogf("s_state: %u\n", (uint32_t)sb->s_state);
  klogf("s_errors: %u\n", (uint32_t)sb->s_errors);
  klogf("s_minor_rev_level: %u\n", (uint32_t)sb->s_minor_rev_level);
  klogf("s_lastcheck: %u\n", sb->s_lastcheck);
  klogf("s_checkinterval: %u\n", sb->s_checkinterval);
  klogf("s_creator_os: %u\n", sb->s_creator_os);
  klogf("s_rev_level: %u\n", sb->s_rev_level);
  klogf("s_def_resuid: %u\n", (uint32_t)sb->s_def_resuid);
  klogf("s_def_resgid: %u\n", (uint32_t)sb->s_def_resgid);

  // EXT2_DYNAMIC_REV Specific
  klogf("s_first_ino: %u\n", sb->s_first_ino);
  klogf("s_inode_size: %u\n", (uint32_t)sb->s_inode_size);
  klogf("s_block_group_nr: %u\n", (uint32_t)sb->s_block_group_nr);
  klogf("s_feature_compat: 0x%x\n", sb->s_feature_compat);
  klogf("s_feature_incompat: 0x%x\n", sb->s_feature_incompat);
  klogf("s_feature_ro_compat: 0x%x\n", sb->s_feature_ro_compat);
  // char s_uuid[16];
  // char s_volume_name[16];
  // char s_last_mounted[64];
  klogf("s_algo_bitmap: 0x%x\n", sb->s_algo_bitmap);

  // Performance Hints
  klogf("s_prealloc_blocks: %u\n", (uint32_t)sb->s_prealloc_blocks);
  klogf("s_prealloc_dir_blocks: %u\n", (uint32_t)sb->s_prealloc_dir_blocks);

  // Journaling Support
  // char s_journal_uuid[16];
  klogf("s_journal_inum: %u\n", sb->s_journal_inum);
  klogf("s_journal_dev: %u\n", sb->s_journal_dev);
  klogf("s_last_orphan: %u\n", sb->s_last_orphan);

  // Directory Indexing Support
  klogf("s_hash_seed[0]: %u\n", sb->s_hash_seed[0]);
  klogf("s_hash_seed[1]: %u\n", sb->s_hash_seed[1]);
  klogf("s_hash_seed[2]: %u\n", sb->s_hash_seed[2]);
  klogf("s_hash_seed[3]: %u\n", sb->s_hash_seed[3]);
  klogf("s_def_hash_version: %u\n", (uint32_t)sb->s_def_hash_version);

  // Other options
  klogf("s_default_mount_options: %u\n", sb->s_default_mount_options);
  klogf("s_first_meta_bg: %u\n", sb->s_first_meta_bg);
}

void ext2_superblock_ltoh(ext2_superblock_t* sb) {
  sb->s_inodes_count = ltoh32(sb->s_inodes_count);
  sb->s_blocks_count = ltoh32(sb->s_blocks_count);
  sb->s_r_blocks_count = ltoh32(sb->s_r_blocks_count);
  sb->s_free_blocks_count = ltoh32(sb->s_free_blocks_count);
  sb->s_free_inodes_count = ltoh32(sb->s_free_inodes_count);
  sb->s_first_data_block = ltoh32(sb->s_first_data_block);
  sb->s_log_block_size = ltoh32(sb->s_log_block_size);
  sb->s_log_frag_size = ltoh32(sb->s_log_frag_size);
  sb->s_blocks_per_group = ltoh32(sb->s_blocks_per_group);
  sb->s_frags_per_group = ltoh32(sb->s_frags_per_group);
  sb->s_inodes_per_group = ltoh32(sb->s_inodes_per_group);
  sb->s_mtime = ltoh32(sb->s_mtime);
  sb->s_wtime = ltoh32(sb->s_wtime);
  sb->s_mnt_count = ltoh16(sb->s_mnt_count);
  sb->s_max_mnt_count = ltoh16(sb->s_max_mnt_count);
  sb->s_magic = ltoh16(sb->s_magic);
  sb->s_state = ltoh16(sb->s_state);
  sb->s_errors = ltoh16(sb->s_errors);
  sb->s_minor_rev_level = ltoh16(sb->s_minor_rev_level);
  sb->s_lastcheck = ltoh32(sb->s_lastcheck);
  sb->s_checkinterval = ltoh32(sb->s_checkinterval);
  sb->s_creator_os = ltoh32(sb->s_creator_os);
  sb->s_rev_level = ltoh32(sb->s_rev_level);
  sb->s_def_resuid = ltoh16(sb->s_def_resuid);
  sb->s_def_resgid = ltoh16(sb->s_def_resgid);

  // EXT2_DYNAMIC_REV Specific
  sb->s_first_ino = ltoh32(sb->s_first_ino);
  sb->s_inode_size = ltoh16(sb->s_inode_size);
  sb->s_block_group_nr = ltoh16(sb->s_block_group_nr);
  sb->s_feature_compat = ltoh32(sb->s_feature_compat);
  sb->s_feature_incompat = ltoh32(sb->s_feature_incompat);
  sb->s_feature_ro_compat = ltoh32(sb->s_feature_ro_compat);
  // char s_uuid[16];
  // char s_volume_name[16];
  // char s_last_mounted[64];
  sb->s_algo_bitmap = ltoh32(sb->s_algo_bitmap);

  // Performance Hints
  // uint8_t s_prealloc_blocks;
  // uint8_t s_prealloc_dir_blocks;
  // char padding1[2];

  // Journaling Support
  // char s_journal_uuid[16];
  sb->s_journal_inum = ltoh32(sb->s_journal_inum);
  sb->s_journal_dev = ltoh32(sb->s_journal_dev);
  sb->s_last_orphan = ltoh32(sb->s_last_orphan);

  // Directory Indexing Support
  sb->s_hash_seed[0] = ltoh32(sb->s_hash_seed[0]);
  sb->s_hash_seed[1] = ltoh32(sb->s_hash_seed[1]);
  sb->s_hash_seed[2] = ltoh32(sb->s_hash_seed[2]);
  sb->s_hash_seed[3] = ltoh32(sb->s_hash_seed[3]);
  // uint8_t s_def_hash_version;
  // char padding2[3];

  // Other options
  sb->s_default_mount_options = ltoh32(sb->s_default_mount_options);
  sb->s_first_meta_bg = ltoh32(sb->s_first_meta_bg);
}

void ext2_block_group_desc_log(ext2_block_group_desc_t* bg) {
  klogf("bg_block_bitmap: %u\n", bg->bg_block_bitmap);
  klogf("bg_inode_bitmap: %u\n", bg->bg_inode_bitmap);
  klogf("bg_inode_table: %u\n", bg->bg_inode_table);
  klogf("bg_free_blocks_count: %u\n", (uint32_t)bg->bg_free_blocks_count);
  klogf("bg_free_inodes_count: %u\n", (uint32_t)bg->bg_free_inodes_count);
  klogf("bg_used_dirs_count: %u\n", (uint32_t)bg->bg_used_dirs_count);
}

void ext2_block_group_desc_ltoh(ext2_block_group_desc_t* bg) {
  bg->bg_block_bitmap = htol32(bg->bg_block_bitmap);
  bg->bg_inode_bitmap = htol32(bg->bg_inode_bitmap);
  bg->bg_inode_table = htol32(bg->bg_inode_table);
  bg->bg_free_blocks_count = htol16(bg->bg_free_blocks_count);
  bg->bg_free_inodes_count = htol16(bg->bg_free_inodes_count);
  bg->bg_used_dirs_count = htol16(bg->bg_used_dirs_count);
}

void ext2_inode_log(ext2_inode_t* i, int long_mode) {
  klogf("i_mode: 0x%x\n", (uint32_t)i->i_mode);
  if (long_mode)
    klogf("i_uid: %u\n", (uint32_t)i->i_uid);
  klogf("i_size: %u\n", i->i_size);
  if (long_mode) {
    klogf("i_atime: %u\n", i->i_atime);
    klogf("i_ctime: %u\n", i->i_ctime);
    klogf("i_mtime: %u\n", i->i_mtime);
    klogf("i_dtime: %u\n", i->i_dtime);
    klogf("i_gid: %u\n", (uint32_t)i->i_gid);
  }
  klogf("i_links_count: %u\n", (uint32_t)i->i_links_count);
  if (long_mode) {
    klogf("i_blocks: %u\n", i->i_blocks);
    klogf("i_flags: 0x%x\n", i->i_flags);
    klogf("i_osd1: %u\n", i->i_osd1);
  }
  for (int idx = 0; idx < 15; ++idx) {
    if (i->i_block[idx] != 0 || long_mode)
      klogf("i_block[%d]: %u\n", idx, i->i_block[idx]);
  }
  if (long_mode) {
    klogf("i_generation: %u\n", i->i_generation);
    klogf("i_file_acl: %u\n", i->i_file_acl);
    klogf("i_dir_acl: %u\n", i->i_dir_acl);
    klogf("i_faddr: %u\n", i->i_faddr);
  }
}

void ext2_inode_ltoh(ext2_inode_t* i) {
  i->i_mode = htol16(i->i_mode);
  i->i_uid = htol16(i->i_uid);
  i->i_size = htol32(i->i_size);
  i->i_atime = htol32(i->i_atime);
  i->i_ctime = htol32(i->i_ctime);
  i->i_mtime = htol32(i->i_mtime);
  i->i_dtime = htol32(i->i_dtime);
  i->i_gid = htol16(i->i_gid);
  i->i_links_count = htol16(i->i_links_count);
  i->i_blocks = htol32(i->i_blocks);
  i->i_flags = htol32(i->i_flags);
  i->i_osd1 = htol32(i->i_osd1);
  for (int idx = 0; idx < 15; ++idx) {
    i->i_block[idx] = htol32(i->i_block[idx]);
  }
  i->i_generation = htol32(i->i_generation);
  i->i_file_acl = htol32(i->i_file_acl);
  i->i_dir_acl = htol32(i->i_dir_acl);
  i->i_faddr = htol32(i->i_faddr);
  // char i_osd2[12];
}

void ext2_dirent_log(ext2_dirent_t* d) {
  klogf("inode: %u\n", d->inode);
  klogf("rec_len: %u\n", (uint32_t)d->rec_len);
  klogf("name_len: %u\n", (uint32_t)d->name_len);
  klogf("file_type: %u\n", (uint32_t)d->file_type);

  char name[256];
  kstrncpy(name, d->name, d->name_len);
  name[d->name_len] = '\0';
  klogf("name: %s\n", name);
}

void ext2_dirent_ltoh(ext2_dirent_t* d) {
  d->inode = htol32(d->inode);
  d->rec_len = htol16(d->rec_len);
}
