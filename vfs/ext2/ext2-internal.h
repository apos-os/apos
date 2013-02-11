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

#ifndef APOO_VFS_EXT2_EXT2_INTERNAL_H
#define APOO_VFS_EXT2_EXT2_INTERNAL_H

#include <stdint.h>

// ext2 superblock structure.
typedef struct {
  uint32_t s_inodes_count;
  uint32_t s_blocks_count;
  uint32_t s_r_blocks_count;
  uint32_t s_free_blocks_count;
  uint32_t s_free_inodes_count;
  uint32_t s_first_data_block;
  uint32_t s_log_block_size;
  uint32_t s_log_frag_size;
  uint32_t s_blocks_per_group;
  uint32_t s_frags_per_group;
  uint32_t s_inodes_per_group;
  uint32_t s_mtime;
  uint32_t s_wtime;
  uint16_t s_mnt_count;
  uint16_t s_max_mnt_count;
  uint16_t s_magic;
  uint16_t s_state;
  uint16_t s_errors;
  uint16_t s_minor_rev_level;
  uint32_t s_lastcheck;
  uint32_t s_checkinterval;
  uint32_t s_creator_os;
  uint32_t s_rev_level;
  uint16_t s_def_resuid;
  uint16_t s_def_resgid;

  // EXT2_DYNAMIC_REV Specific
  uint32_t s_first_ino;
  uint16_t s_inode_size;
  uint16_t s_block_group_nr;
  uint32_t s_feature_compat;
  uint32_t s_feature_incompat;
  uint32_t s_feature_ro_compat;
  char s_uuid[16];
  char s_volume_name[16];
  char s_last_mounted[64];
  uint32_t s_algo_bitmap;

  // Performance Hints
  uint8_t s_prealloc_blocks;
  uint8_t s_prealloc_dir_blocks;
  char padding1[2];

  // Journaling Support
  char s_journal_uuid[16];
  uint32_t s_journal_inum;
  uint32_t s_journal_dev;
  uint32_t s_last_orphan;

  // Directory Indexing Support
  uint32_t s_hash_seed[4];
  uint8_t s_def_hash_version;
  char padding2[3];

  // Other options
  uint32_t s_default_mount_options;
  uint32_t s_first_meta_bg;

  // char padding3[760];
} __attribute__((packed)) ext2_superblock_t;
_Static_assert(sizeof(ext2_superblock_t) + 760 == 1024,
               "ext2 superblock incorrect size");

// Convert a superblock from host endian to little endian.
void ext2_superblock_htol(ext2_superblock_t* sb);

#endif
