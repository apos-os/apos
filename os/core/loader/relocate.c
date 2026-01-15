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
#include "os/core/loader/relocate.h"

#include "os/core/loader/gnu_hash.h"
#include "os/core/loader/ld_assert.h"
#include "os/core/loader/ld_printf.h"
#include "os/core/loader/ld_string.h"
#include "os/core/loader/syscalls.h"
#include "proc/load/elf-riscv.h"

typedef enum {
  LK_NORMAL,
  LK_SKIP_EXEC,
} lk_mode_t;

typedef struct {
  const Elf64_Sym* sym;
  const lib_t* lib;
} lookup_t;

// Looks up the given symbol in the current context.  Returns NULL if the symbol
// can't be found, but it shouldn't be considered an error.
static lookup_t lookup(const ctx_t* ctx, const lib_t* lib, uint32_t symbol,
                       lk_mode_t mode) {
  const Elf64_Sym* src_sym = &lib->dyn.symtab[symbol];
  const char* symbol_str = lib->dyn.strtab + src_sym->st_name;
  LOG(4, "lookup(%s:%s) -> ", lib->so_name, symbol_str);
  uint32_t hash = gnu_hash(symbol_str);

  // TODO(aoates): support DT_SYMBOLIC here.
  const lib_t* lookup_lib = (mode == LK_NORMAL) ? ctx->libs : ctx->libs->next;
  while (lookup_lib) {
    const Elf64_Sym* target =
        gnu_hash_lookup(&lookup_lib->dyn, symbol_str, hash);
    if (target && target->st_shndx != 0) {
      LOG(4, "%s@%p\n", lookup_lib->so_name, (void*)target->st_value);
      return (lookup_t){target, lookup_lib};
    }
    lookup_lib = lookup_lib->next;
  }
  if (ELF64_ST_BIND(src_sym->st_info) == STB_WEAK) {
    // If we can't find another definition of a weak symbol, ignore it.
    // TODO(aoates): is this actually correct behavior?  Test it.
    LOG(2, "Unable to resolve weak symbol %s\n", symbol_str);
  } else {
    LOG(0, "Error: unable to resolve symbol %s\n", symbol_str);
    ld_exit(1);
  }
  return (lookup_t){NULL, NULL};
}

static void handle_copy_reloc(const ctx_t* ctx, lib_t* lib,
                              const Elf64_Rela* r) {
  lookup_t sym = lookup(ctx, lib, ELF64_R_SYM(r->r_info), LK_SKIP_EXEC);
  KASSERT(sym.sym);  // TODO(aoates): is this correct for weak symbols?)
  const Elf64_Sym* src_sym = &lib->dyn.symtab[ELF64_R_SYM(r->r_info)];

  KASSERT(src_sym->st_value == r->r_offset);
  KASSERT(src_sym->st_size == sym.sym->st_size);
  kmemcpy((void*)(lib->bin->base_addr + src_sym->st_value),
          (void*)(sym.lib->bin->base_addr + sym.sym->st_value),
          src_sym->st_size);
}

static void do_rela(const ctx_t* ctx, lib_t* lib) {
  uint64_t base_addr = lib->bin->base_addr;
  const elf64_dyninfo_t* dyn = &lib->dyn;

  LOG(2, "Found %lu RELA relocations\n", dyn->rela_count);
  for (size_t i = 0; i < dyn->rela_count; ++i) {
    const Elf64_Rela* r = &dyn->rela[i];
    LOG(3,
        "RELA[%lu] = { r_offset = 0x%lx, r_info = 0x%lx, r_addend = 0x%li }\n",
        i, r->r_offset, r->r_info, r->r_addend);
    _Static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "");
    int rtype = ELF64_R_TYPE(dyn->rela[i].r_info);
    bool add_symbol = false;
    uint64_t val = 0;
    switch (rtype) {
      case R_RISCV_64:
        add_symbol = true;
        val = r->r_addend;
        break;

      case R_RISCV_RELATIVE:
        val = base_addr + r->r_addend;
        break;

      case R_RISCV_COPY:
        handle_copy_reloc(ctx, lib, r);
        continue;

      case R_RISCV_JUMP_SLOT:
        add_symbol = true;
        val = 0;
        break;

      default:
        ld_printf("Error: unknown relocation type %d\n", rtype);
        ld_exit(1);
    }
    if (add_symbol) {
      lookup_t sym =
          lookup(ctx, lib, ELF64_R_SYM(dyn->rela[i].r_info), LK_NORMAL);
      if (!sym.sym) {
        continue;
      }
      val += sym.sym->st_value + sym.lib->bin->base_addr;
    }
    *(uint64_t*)(base_addr + r->r_offset) = val;
  }
}

void elf64_relocate(const ctx_t* ctx, lib_t* lib) {
  LOG(2, "Relocating %s\n", lib->so_name);
  do_rela(ctx, lib);
}
