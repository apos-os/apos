// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#include <limits.h>
#include <stdint.h>

#include "os/core/loader/elf64.h"
#include "os/core/loader/ld_assert.h"
#include "os/core/loader/ld_printf.h"
#include "os/core/loader/ld_string.h"
#include "os/core/loader/map.h"
#include "os/core/loader/syscalls.h"
#include "proc/load/elf-internal.h"
#include "proc/load/elf-riscv.h"
#include "user/include/apos/auxvec.h"

unsigned long apos_auxval_get(unsigned long type);

static const char kTestString[] = "Test String";
static const char* kTestStringPtr = kTestString;

typedef void (*start_ptr_type)(char* argv[], char* envp[],
                               const apos_auxv_t* auxv);

void ld_main(int argc, char *argv[], char *envp[], const apos_auxv_t* auxv) {
  int val = 0;
  LOG(2, "Running loader.\n");
  LOG(2, "  Args (argc = %d):\n", argc);
  for (int i = 0; i < argc; ++i) {
    LOG(2, "    argv[%d] = '%s'\n", i, argv[i]);
  }
  LOG(2, "  Current stack ptr is %p\n", &val);
  LOG(2, "  Address of main() is %p\n", &ld_main);
  LOG(2, "  __builtin_return_address(0): %p\n", __builtin_return_address(0));
  LOG(2, "  kTestString: '%s'\n", kTestStringPtr);

  // Load and execute the main binary.
  int exec_fd = apos_auxval_get(AUXVEC_EXEC_FD);
  KASSERT(exec_fd >= 0 && exec_fd < 20000);
  load_binary_t* exec_bin = NULL;
  int result = elf64_load(exec_fd, &exec_bin);
  if (result) {
    LOG(0, "Error: unable to load exec fd as ELF64\n");
    ld_exit(1);
  }

  result = load_map_binary(exec_fd, exec_bin);
  if (result) {
    LOG(0, "Error: unable to load executable\n");
    ld_exit(1);
  }

  // Jump to the entry point; we should never return.
  LOG(1, "Jumping to user executable entry at %p\n", (void*)exec_bin->entry);
  start_ptr_type start = (start_ptr_type)exec_bin->entry;
  (*start)(argv, envp, auxv);

  ld_exit(0);
}

static void do_relocate(uint64_t base_addr, const elf64_dyninfo_t* dyn) {
  LOG(2, "Found %lu RELA relocations\n", dyn->rela_count);
  for (size_t i = 0; i < dyn->rela_count; ++i) {
    const Elf64_Rela* r = &dyn->rela[i];
    LOG(3,
        "RELA[%lu] = { r_offset = 0x%lx, r_info = 0x%lx, r_addend = 0x%li }\n",
        i, r->r_offset, r->r_info, r->r_addend);
    _Static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "");
    int rtype = ELF64_R_TYPE(dyn->rela[i].r_info);
    switch (rtype) {
      case R_RISCV_RELATIVE:
        *(uint64_t*)(base_addr + r->r_offset) = base_addr + r->r_addend;
        break;

      default:
        ld_printf("Error: unknown relocation type %d\n", rtype);
        ld_exit(1);
    }
  }
}

static void relocate_me(uintptr_t base_addr) {
  const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)base_addr;
  int result = elf64_check_header(ehdr);
  if (result != 0) {
    ld_printf("Error: can't find loader's ELF header at 0x%lx\n", base_addr);
    ld_exit(1);
  }
  KASSERT(ehdr->e_phentsize == sizeof(Elf64_Phdr));
  LOG(2, "Found loader ELF header at 0x%lx\n", base_addr);
#define X(field, printf) LOG(2, "  " #field ": " printf "\n", ehdr->field)
  X(e_type, "%u");
  X(e_machine, "%u");
  X(e_version, "%u");
  X(e_entry, "0x%lx");
  X(e_phoff, "0x%lx");
  X(e_shoff, "0x%lx");
  X(e_flags, "%u");
  X(e_ehsize, "%u");
  X(e_phentsize, "%u");
  X(e_phnum, "%u");
  X(e_shentsize, "%u");
  X(e_shnum, "%u");
  X(e_shstrndx, "%u");
#undef X

  const Elf64_Dyn* dyns =
      elf64_find_dynamic(base_addr, ehdr, ELF_MAPPED_LOADED);
  KASSERT(dyns != NULL);
  elf64_dyninfo_t dyn;
  KASSERT(0 == elf64_parse_dynamic(base_addr, ehdr, dyns, &dyn));

  do_relocate(base_addr, &dyn);
}

static const apos_auxv_t* g_auxv;

unsigned long apos_auxval_get(unsigned long type) {
  const apos_auxv_t* aux = g_auxv;
  while (aux) {
    if (aux->a_type == type) {
      unsigned long val = aux->a_val;
#if ULONG_MAX == UINT64_MAX
      val |= (unsigned long)aux->a_val_hi << 32;
#endif
      return val;
    }
    aux++;
  }
  return 0;
}

void _start(char** argv, char** envp, const apos_auxv_t* auxv) {
#if defined(__riscv)
  asm volatile (
    ".option push\n\t"
    ".option norelax\n\t"
    "1: auipc gp, %pcrel_hi(__global_pointer$)\n\t"
    "   addi  gp, gp, %pcrel_lo(1b)\n\t"
    ".option pop\n\t");
#endif
  int argc = 0;
  while (argv[argc] != 0x0) argc++;
  g_auxv = auxv;

  const uintptr_t base_addr = apos_auxval_get(AUXVEC_BASE);
  relocate_me(base_addr);

  KASSERT(PAGE_SIZE == apos_auxval_get(AUXVEC_PAGESZ));

  ld_main(argc, argv, envp, auxv);
  // Should never get here.
  LOG(0, "Error: ld shouldn't return from ld_main\n");
  ld_exit(1);
}
