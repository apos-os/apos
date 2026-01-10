// Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#include "os/core/loader/elf64.h"

#include <errno.h>

#include "os/core/loader/ld_printf.h"

int elf64_check_header(const Elf64_Ehdr* header) {
  if (header->e_ident[EI_MAG0] != ELFMAG0 ||
      header->e_ident[EI_MAG1] != ELFMAG1 ||
      header->e_ident[EI_MAG2] != ELFMAG2 ||
      header->e_ident[EI_MAG3] != ELFMAG3) {
    return -EINVAL;
  }

  if (header->e_ident[EI_CLASS] != ELFCLASS64 ||
      header->e_ident[EI_DATA] != ELFDATA2LSB) {
    ld_printf("unsupported ELF64 format (must be 64-bit, little endian)\n");
    return -EINVAL;
  }

  if (header->e_ident[EI_VERSION] != EV_CURRENT ||
      header->e_version != EV_CURRENT) {
    ld_printf("unknown ELF version (%d/%d)\n", header->e_ident[EI_VERSION],
         header->e_version);
    return -EINVAL;
  }

  if (header->e_type != ET_EXEC && header->e_type != ET_DYN) {
    ld_printf("ELF type != ET_EXEC/ET_DYN (%d)\n", header->e_type);
    return -EINVAL;
  }

  if (header->e_machine != EM_RISCV) {
    ld_printf("Unsupported ELF e_machine (%d)\n", header->e_machine);
    return -EINVAL;
  }

  if (header->e_type == ET_EXEC && header->e_entry == 0) {
    ld_printf("ELF missing entry point\n");
    return -EINVAL;
  }

  if (header->e_phoff == 0) {
    ld_printf("ELF missing program header table\n");
    return -EINVAL;
  }

  if (header->e_phentsize != sizeof(Elf64_Phdr)) {
    // TODO(aoates): support this.
    ld_printf("unsupported program header entry size (%d)\n",
         header->e_phentsize);
    return -ENOTSUP;
  }

  return 0;
}
