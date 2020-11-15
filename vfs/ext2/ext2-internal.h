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

#include "common/klog.h"

// ext2 superblock structure.
typedef struct {
  uint32_t s_inodes_count;  // const after creation
  uint32_t s_blocks_count;  // const after creation
  uint32_t s_r_blocks_count;
  uint32_t s_free_blocks_count;
  uint32_t s_free_inodes_count;
  uint32_t s_first_data_block;  // const after creation
  uint32_t s_log_block_size;    // const after creation
  uint32_t s_log_frag_size;     // const after creation
  uint32_t s_blocks_per_group;  // const after creation
  uint32_t s_frags_per_group;   // const after creation
  uint32_t s_inodes_per_group;  // const after creation
  uint32_t s_mtime;
  uint32_t s_wtime;
  uint16_t s_mnt_count;
  uint16_t s_max_mnt_count;
  uint16_t s_magic;  // const after creation
  uint16_t s_state;
  uint16_t s_errors;
  uint16_t s_minor_rev_level;  // const after creation
  uint32_t s_lastcheck;
  uint32_t s_checkinterval;
  uint32_t s_creator_os;
  uint32_t s_rev_level;  // const after creation
  uint16_t s_def_resuid;
  uint16_t s_def_resgid;

  // EXT2_DYNAMIC_REV Specific
  uint32_t s_first_ino;   // const after creation
  uint16_t s_inode_size;  // const after creation
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

#define EXT2_SUPER_MAGIC 0xEF53

// ext2_superblock_t::s_state
#define EXT2_VALID_FS 1  // Unmounted cleanly
#define EXT2_ERROR_FS 2  // Errors detected

// ext2_superblock_t::s_errors
#define EXT2_ERRORS_CONTINUE 1  // Continue as if nothing happened
#define EXT2_ERRORS_RO 2  // Remount read-only
#define EXT2_ERRORS_PANIC 3  // Cause a kernel panic

// ext2_superblock_t::s_creator_os
#define EXT2_OS_LINUX 0  // Linux
#define EXT2_OS_HURD 1  // GNU HURD
#define EXT2_OS_MASIX 2  // MASIX
#define EXT2_OS_FREEBSD 3  // FreeBSD
#define EXT2_OS_LITES 4  // Lites

// ext2_superblock_t::s_rev_level
#define EXT2_GOOD_OLD_REV 0  // Revision 0
#define EXT2_DYNAMIC_REV 1  // Revision 1 with variable inode sizes, extended attributes, etc.

// ext2_superblock_t::s_feature_compat
#define EXT2_FEATURE_COMPAT_DIR_PREALLOC 0x0001  // Block pre-allocation for new directories
#define EXT2_FEATURE_COMPAT_IMAGIC_INODES 0x0002
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL 0x0004  // An Ext3 journal exists
#define EXT2_FEATURE_COMPAT_EXT_ATTR 0x0008  // Extended inode attributes are present
#define EXT2_FEATURE_COMPAT_RESIZE_INO 0x0010  // Non-standard inode size used
#define EXT2_FEATURE_COMPAT_DIR_INDEX 0x0020  // Directory indexing (HTree)

// ext2_superblock_t::s_feature_incompat
#define EXT2_FEATURE_INCOMPAT_COMPRESSION 0x0001  // Disk/File compression is used
#define EXT2_FEATURE_INCOMPAT_FILETYPE 0x0002
#define EXT3_FEATURE_INCOMPAT_RECOVER 0x0004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV 0x0008
#define EXT2_FEATURE_INCOMPAT_META_BG 0x0010

// ext2_superblock_t::s_feature_ro_compat
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER 0x0001  // Sparse Superblock
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE 0x0002  // Large file support, 64-bit file size
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR 0x0004  // Binary tree sorted directory files

// ext2_superblock_t::s_algo_bitmap
#define EXT2_LZV1_ALG 0x00000001
#define EXT2_LZRW3A_ALG 0x00000002
#define EXT2_GZIP_ALG 0x00000004
#define EXT2_BZIP2_ALG 0x00000008
#define EXT2_LZO_ALG 0x00000010

void ext2_superblock_log(klog_level_t level, ext2_superblock_t* sb);

// Convert a superblock from host endian to little endian.
void ext2_superblock_ltoh(ext2_superblock_t* sb);

typedef struct {
  uint32_t bg_block_bitmap;  // const after creation
  uint32_t bg_inode_bitmap;  // const after creation
  uint32_t bg_inode_table;   // const after creation
  uint16_t bg_free_blocks_count;
  uint16_t bg_free_inodes_count;
  uint16_t bg_used_dirs_count;
  uint16_t bg_pad;
  char bg_reserved[12];
} __attribute__((packed)) ext2_block_group_desc_t;
_Static_assert(sizeof(ext2_block_group_desc_t) == 32,
               "ext2 block group descriptor incorrect size");
void ext2_block_group_desc_log(klog_level_t level, ext2_block_group_desc_t* bg);
void ext2_block_group_desc_ltoh(ext2_block_group_desc_t* bg);

typedef struct {
  uint16_t i_mode;
  uint16_t i_uid;
  uint32_t i_size;
  uint32_t i_atime;
  uint32_t i_ctime;
  uint32_t i_mtime;
  uint32_t i_dtime;
  uint16_t i_gid;
  uint16_t i_links_count;
  uint32_t i_blocks;
  uint32_t i_flags;
  uint32_t i_osd1;
  uint32_t i_block[15];
  uint32_t i_generation;
  uint32_t i_file_acl;
  uint32_t i_dir_acl;
  uint32_t i_faddr;
  char i_osd2[12];
} __attribute__((packed)) ext2_inode_t;
_Static_assert(sizeof(ext2_inode_t) == 128,
               "ext2 inode incorrect size");
void ext2_inode_log(klog_level_t level, ext2_inode_t* i, int long_mode);
void ext2_inode_ltoh(ext2_inode_t* i);

// Reserved ext2 inodes.
#define EXT2_BAD_INO 1  // bad blocks inode
#define EXT2_ROOT_INO 2  // root directory inode
#define EXT2_ACL_IDX_INO 3  // ACL index inode (deprecated?)
#define EXT2_ACL_DATA_INO 4  // ACL data inode (deprecated?)
#define EXT2_BOOT_LOADER_INO 5  // boot loader inode
#define EXT2_UNDEL_DIR_INO 6  // undelete directory inode

// inode i_mode flags.
// file format
#define EXT2_S_IFSOCK 0xC000  // socket
#define EXT2_S_IFLNK 0xA000  // symbolic link
#define EXT2_S_IFREG 0x8000  // regular file
#define EXT2_S_IFBLK 0x6000  // block device
#define EXT2_S_IFDIR 0x4000  // directory
#define EXT2_S_IFCHR 0x2000  // character device
#define EXT2_S_IFIFO 0x1000  // fifo
#define EXT2_S_MASK  0xF000
// process execution user/group override
#define EXT2_S_ISUID 0x0800  // Set process User ID
#define EXT2_S_ISGID 0x0400  // Set process Group ID
#define EXT2_S_ISVTX 0x0200  // sticky bit
// access rights
#define EXT2_S_IRUSR 0x0100  // user read
#define EXT2_S_IWUSR 0x0080  // user write
#define EXT2_S_IXUSR 0x0040  // user execute
#define EXT2_S_IRGRP 0x0020  // group read
#define EXT2_S_IWGRP 0x0010  // group write
#define EXT2_S_IXGRP 0x0008  // group execute
#define EXT2_S_IROTH 0x0004  // others read
#define EXT2_S_IWOTH 0x0002  // others write
#define EXT2_S_IXOTH 0x0001  // others execute

typedef struct {
  uint32_t inode;
  uint16_t rec_len;
  uint8_t name_len;
  uint8_t file_type;
  char name[];
} ext2_dirent_t;
void ext2_dirent_log(klog_level_t level, ext2_dirent_t* d);
void ext2_dirent_ltoh(ext2_dirent_t* d);

// The minimum size (in bytes) of a dirent_t with the given name length.
static inline uint16_t ext2_dirent_min_size(int name_len) {
  uint16_t size = sizeof(ext2_dirent_t) + name_len;
  return (size % 4) ? ((size / 4 + 1) * 4) : size;
}

#define EXT2_FT_UNKNOWN 0  // Unknown File Type
#define EXT2_FT_REG_FILE 1  // Regular File
#define EXT2_FT_DIR 2  // Directory File
#define EXT2_FT_CHRDEV 3  // Character Device
#define EXT2_FT_BLKDEV 4  // Block Device
#define EXT2_FT_FIFO 5  // Buffer File
#define EXT2_FT_SOCK 6  // Socket File
#define EXT2_FT_SYMLINK 7  // Symbolic Link

#endif
