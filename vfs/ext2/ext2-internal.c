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

void ext2_superblock_htol(ext2_superblock_t* sb) {
  htol32(sb->s_inodes_count);
  htol32(sb->s_blocks_count);
  htol32(sb->s_r_blocks_count);
  htol32(sb->s_free_blocks_count);
  htol32(sb->s_free_inodes_count);
  htol32(sb->s_first_data_block);
  htol32(sb->s_log_block_size);
  htol32(sb->s_log_frag_size);
  htol32(sb->s_blocks_per_group);
  htol32(sb->s_frags_per_group);
  htol32(sb->s_inodes_per_group);
  htol32(sb->s_mtime);
  htol32(sb->s_wtime);
  htol16(sb->s_mnt_count);
  htol16(sb->s_max_mnt_count);
  htol16(sb->s_magic);
  htol16(sb->s_state);
  htol16(sb->s_errors);
  htol16(sb->s_minor_rev_level);
  htol32(sb->s_lastcheck);
  htol32(sb->s_checkinterval);
  htol32(sb->s_creator_os);
  htol32(sb->s_rev_level);
  htol16(sb->s_def_resuid);
  htol16(sb->s_def_resgid);

  // EXT2_DYNAMIC_REV Specific
  htol32(sb->s_first_ino);
  htol16(sb->s_inode_size);
  htol16(sb->s_block_group_nr);
  htol32(sb->s_feature_compat);
  htol32(sb->s_feature_incompat);
  htol32(sb->s_feature_ro_compat);
  // char s_uuid[16];
  // char s_volume_name[16];
  // char s_last_mounted[64];
  htol32(sb->s_algo_bitmap);

  // Performance Hints
  // uint8_t s_prealloc_blocks;
  // uint8_t s_prealloc_dir_blocks;
  // char padding1[2];

  // Journaling Support
  // char s_journal_uuid[16];
  htol32(sb->s_journal_inum);
  htol32(sb->s_journal_dev);
  htol32(sb->s_last_orphan);

  // Directory Indexing Support
  htol32(sb->s_hash_seed[0]);
  htol32(sb->s_hash_seed[1]);
  htol32(sb->s_hash_seed[2]);
  htol32(sb->s_hash_seed[3]);
  // uint8_t s_def_hash_version;
  // char padding2[3];

  // Other options
  htol32(sb->s_default_mount_options);
  htol32(sb->s_first_meta_bg);
}
