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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "memory/kmalloc.h"
#include "memory/flags.h"
#include "proc/load/elf.h"
#include "proc/load/elf-internal.h"
#include "vfs/vfs.h"

#define KLOG(...) klogfm(KL_PROC, __VA_ARGS__)

// Attempt to read exactly count bytes.  Read until we get there, or hit EOF.
// Returns 0 if we read exactly count bytes, error if otherwise.
static int elf64_read_bytes(int fd, void* buf, unsigned int count) {
  unsigned int bytes_read = 0;
  while (bytes_read < count) {
    const int result = vfs_read(fd, buf + bytes_read,
                                count - bytes_read);
    if (result < 0) {
      return result;
    } else if (result == 0) {
      return -EINVAL;
    }
    bytes_read += result;
  }
  return 0;
}

// Checks the validity of an Elf64_Ehdr.  Returns 0 if it's valid (i.e., we can
// load the file with that header).
static int elf64_check_header(const Elf64_Ehdr* header) {
  if (header->e_ident[EI_MAG0] != ELFMAG0 ||
      header->e_ident[EI_MAG1] != ELFMAG1 ||
      header->e_ident[EI_MAG2] != ELFMAG2 ||
      header->e_ident[EI_MAG3] != ELFMAG3) {
    return -EINVAL;
  }

  if (header->e_ident[EI_CLASS] != ELFCLASS64 ||
      header->e_ident[EI_DATA] != ELFDATA2LSB) {
    KLOG(DEBUG, "unsupported ELF64 format (must be 64-bit, little endian)\n");
    return -EINVAL;
  }

  if (header->e_ident[EI_VERSION] != EV_CURRENT ||
      header->e_version != EV_CURRENT) {
    KLOG(INFO, "unknown ELF version (%d/%d)\n", header->e_ident[EI_VERSION],
         header->e_version);
    return -EINVAL;
  }

  if (header->e_type != ET_EXEC) {
    KLOG(INFO, "ELF type != ET_EXEC (%d)\n", header->e_type);
    return -EINVAL;
  }

  if (header->e_machine != EM_RISCV) {
    KLOG(INFO, "Unsupported ELF e_machine (%d)\n", header->e_machine);
    return -EINVAL;
  }

  if (header->e_entry == 0) {
    KLOG(INFO, "ELF missing entry point\n");
    return -EINVAL;
  }

  if (header->e_phoff == 0) {
    KLOG(INFO, "ELF missing program header table\n");
    return -EINVAL;
  }

  if (header->e_phentsize != sizeof(Elf64_Phdr)) {
    // TODO(aoates): support this.
    KLOG(INFO, "unsupported program header entry size (%d)\n",
         header->e_phentsize);
    return -ENOTSUP;
  }

  return 0;
}

static int elf64_read_phdrs(int fd, const Elf64_Ehdr* header, Elf64_Phdr* phdrs) {
  int result = vfs_seek(fd, header->e_phoff, VFS_SEEK_SET);
  if (result < 0) return result;

  for (int i = 0; i < header->e_phnum; ++i) {
    int result = elf64_read_bytes(fd, phdrs + i, sizeof(Elf64_Phdr));
    if (result) return result;

    if (phdrs[i].p_type != PT_NULL &&
        phdrs[i].p_type != PT_LOAD &&
        phdrs[i].p_type != PT_NOTE &&
        phdrs[i].p_type != PT_GNU_STACK &&
        phdrs[i].p_type != PT_RISCV_ATTRIBUTES) {
      KLOG(INFO, "unsupported ELF program segment type 0x%x (segment %d)\n",
           phdrs[i].p_type, i);
      return -EINVAL;
    }

    // TODO(aoates): check p_align?
  }

  return 0;
}

static int elf64_create_load_binary(const Elf64_Ehdr* header,
                                    const Elf64_Phdr* phdrs,
                                    load_binary_t** binary_out) {
  int num_regions = 0;
  for (int i = 0; i < header->e_phnum; ++i) {
    if (phdrs[i].p_type == PT_LOAD) ++num_regions;
  }

  load_binary_t* bin = (load_binary_t*)kmalloc(
      sizeof(load_binary_t) + sizeof(load_region_t) * num_regions);
  *binary_out = bin;

  KASSERT_DBG(header->e_ident[EI_CLASS] == ELFCLASS64);
  KASSERT_DBG(header->e_machine == EM_RISCV);
  bin->arch = BIN_RISCV_64;
  bin->entry = header->e_entry;
  bin->num_regions = num_regions;
  int region_number = 0;
  for (int i = 0; i < header->e_phnum; ++i) {
    if (phdrs[i].p_type != PT_LOAD) continue;
    load_region_t* region = &bin->regions[region_number++];
    region->file_offset = phdrs[i].p_offset;
    region->vaddr = phdrs[i].p_vaddr;
    region->file_len = phdrs[i].p_filesz;
    region->mem_len = phdrs[i].p_memsz;

    region->prot = 0;
    if (phdrs[i].p_flags & PF_R) region->prot |= MEM_PROT_READ;
    if (phdrs[i].p_flags & PF_W) region->prot |= MEM_PROT_WRITE;
    if (phdrs[i].p_flags & PF_X) region->prot |= MEM_PROT_EXEC;
  }

  return 0;
}

int elf64_is_loadable(int fd) {
  int result = vfs_seek(fd, 0, VFS_SEEK_SET);
  if (result < 0) return result;

  // Read the ELF header.
  Elf64_Ehdr header;
  result = elf64_read_bytes(fd, &header, sizeof(Elf64_Ehdr));
  if (result != 0) return result;

  // Check the header contents.
  return elf64_check_header(&header);
}

int elf64_load(int fd, load_binary_t** binary_out) {
  int result = vfs_seek(fd, 0, VFS_SEEK_SET);
  if (result < 0) return result;

  // Read the ELF header.
  Elf64_Ehdr header;
  result = elf64_read_bytes(fd, &header, sizeof(Elf64_Ehdr));
  if (result != 0) return result;

  // Check the header contents.
  result = elf64_check_header(&header);
  if (result != 0) return result;

  // Read the program header.
  Elf64_Phdr* phdrs = (Elf64_Phdr*)kmalloc(sizeof(Elf64_Phdr) * header.e_phnum);
  result = elf64_read_phdrs(fd, &header, phdrs);
  if (result) {
    kfree(phdrs);
    return result;
  }

  // Create a load_binary_t* from it.
  result = elf64_create_load_binary(&header, phdrs, binary_out);
  kfree(phdrs);
  return result;
}
