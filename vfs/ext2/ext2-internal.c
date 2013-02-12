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

void ext2_superblock_htol(ext2_superblock_t* sb) {
  sb->s_inodes_count = htol32(sb->s_inodes_count);
  sb->s_blocks_count = htol32(sb->s_blocks_count);
  sb->s_r_blocks_count = htol32(sb->s_r_blocks_count);
  sb->s_free_blocks_count = htol32(sb->s_free_blocks_count);
  sb->s_free_inodes_count = htol32(sb->s_free_inodes_count);
  sb->s_first_data_block = htol32(sb->s_first_data_block);
  sb->s_log_block_size = htol32(sb->s_log_block_size);
  sb->s_log_frag_size = htol32(sb->s_log_frag_size);
  sb->s_blocks_per_group = htol32(sb->s_blocks_per_group);
  sb->s_frags_per_group = htol32(sb->s_frags_per_group);
  sb->s_inodes_per_group = htol32(sb->s_inodes_per_group);
  sb->s_mtime = htol32(sb->s_mtime);
  sb->s_wtime = htol32(sb->s_wtime);
  sb->s_mnt_count = htol16(sb->s_mnt_count);
  sb->s_max_mnt_count = htol16(sb->s_max_mnt_count);
  sb->s_magic = htol16(sb->s_magic);
  sb->s_state = htol16(sb->s_state);
  sb->s_errors = htol16(sb->s_errors);
  sb->s_minor_rev_level = htol16(sb->s_minor_rev_level);
  sb->s_lastcheck = htol32(sb->s_lastcheck);
  sb->s_checkinterval = htol32(sb->s_checkinterval);
  sb->s_creator_os = htol32(sb->s_creator_os);
  sb->s_rev_level = htol32(sb->s_rev_level);
  sb->s_def_resuid = htol16(sb->s_def_resuid);
  sb->s_def_resgid = htol16(sb->s_def_resgid);

  // EXT2_DYNAMIC_REV Specific
  sb->s_first_ino = htol32(sb->s_first_ino);
  sb->s_inode_size = htol16(sb->s_inode_size);
  sb->s_block_group_nr = htol16(sb->s_block_group_nr);
  sb->s_feature_compat = htol32(sb->s_feature_compat);
  sb->s_feature_incompat = htol32(sb->s_feature_incompat);
  sb->s_feature_ro_compat = htol32(sb->s_feature_ro_compat);
  // char s_uuid[16];
  // char s_volume_name[16];
  // char s_last_mounted[64];
  sb->s_algo_bitmap = htol32(sb->s_algo_bitmap);

  // Performance Hints
  // uint8_t s_prealloc_blocks;
  // uint8_t s_prealloc_dir_blocks;
  // char padding1[2];

  // Journaling Support
  // char s_journal_uuid[16];
  sb->s_journal_inum = htol32(sb->s_journal_inum);
  sb->s_journal_dev = htol32(sb->s_journal_dev);
  sb->s_last_orphan = htol32(sb->s_last_orphan);

  // Directory Indexing Support
  sb->s_hash_seed[0] = htol32(sb->s_hash_seed[0]);
  sb->s_hash_seed[1] = htol32(sb->s_hash_seed[1]);
  sb->s_hash_seed[2] = htol32(sb->s_hash_seed[2]);
  sb->s_hash_seed[3] = htol32(sb->s_hash_seed[3]);
  // uint8_t s_def_hash_version;
  // char padding2[3];

  // Other options
  sb->s_default_mount_options = htol32(sb->s_default_mount_options);
  sb->s_first_meta_bg = htol32(sb->s_first_meta_bg);
}
