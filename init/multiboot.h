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

#ifndef APOO_LOAD_MULTIBOOT_H
#define APOO_LOAD_MULTIBOOT_H

#include <stdint.h>

// Constants in the flags field.
#define MULTIBOOT_INFO_MEMORY           0x001
#define MULTIBOOT_INFO_BOOTDEV          0x002
#define MULTIBOOT_INFO_CMDLINE          0x004
#define MULTIBOOT_INFO_MODS             0x008
#define MULTIBOOT_INFO_SYMS_AOUT        0x010
#define MULTIBOOT_INFO_SYMS_ELF         0x020
#define MULTIBOOT_INFO_MMAP             0x040
#define MULTIBOOT_INFO_DRIVES           0x080
#define MULTIBOOT_INFO_CONFIG_TABLE     0x100
#define MULTIBOOT_INFO_BOOT_LOADER_NAME 0x200
#define MULTIBOOT_INFO_APM_TABLE        0x400
#define MULTIBOOT_INFO_VIDEO_INFO       0x800

struct multiboot_info_sym_aout {
  uint32_t tabsize;
  uint32_t strsize;
  uint32_t addr;
  uint32_t reserved;
};
typedef struct multiboot_info_sym_aout multiboot_info_sym_aout_t;

struct multiboot_info_sym_elf {
  uint32_t num;
  uint32_t size;
  uint32_t addr;
  uint32_t shndx;
};
typedef struct multiboot_info_sym_elf multiboot_info_sym_elf_t;

// Multiboot information struct.  See
// http://www.gnu.org/software/grub/manual/multiboot/multiboot.html
struct multiboot_info {
  uint32_t flags;
  uint32_t mem_lower;
  uint32_t mem_upper;
  uint32_t boot_device;
  uint32_t cmdline;
  uint32_t mods_count;
  uint32_t mods_addr;

  union {
    multiboot_info_sym_aout_t aout;
    multiboot_info_sym_elf_t elf;
  } syms;

  uint32_t mmap_length;
  uint32_t mmap_addr;
  uint32_t drives_length;
  uint32_t drives_addr;
  uint32_t config_table;
  uint32_t boot_loader_name;
  uint32_t apm_table;
  uint32_t vbe_control_info;
  uint32_t vbe_mode_info;
  uint16_t vbe_mode;
  uint16_t vbe_interface_seg;
  uint16_t vbe_interface_off;
  uint16_t vbe_interface_len;
};
typedef struct multiboot_info multiboot_info_t;

#endif
