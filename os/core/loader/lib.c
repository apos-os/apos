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
#include "os/core/loader/lib.h"

#include <apos/mmap.h>
#include <apos/syscall_decls.h>
#include <apos/vfs/vfs.h>
#include <stdbool.h>
#include <stddef.h>

#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/math.h"
#include "os/core/loader/elf64.h"
#include "os/core/loader/gnu_hash.h"
#include "os/core/loader/ld_alloc.h"
#include "os/core/loader/ld_assert.h"
#include "os/core/loader/ld_printf.h"
#include "os/core/loader/map.h"
#include "os/core/loader/relocate.h"
#include "os/core/loader/syscalls.h"
#include "proc/load/elf-internal.h"

// TODO(aoates): determine this dynamically?
static const char* kLibPath[] = {
  "/lib",
  "/usr/lib",
  NULL,
};

static int find_lib(lib_t* lib) {
  KASSERT(lib->state == LIB_NEEDED);
  const int kBufSize = 200;
  char path[kBufSize];
  for (int i = 0; kLibPath[i] != NULL; ++i) {
    ksnprintf(path, kBufSize, "%s/%s", kLibPath[i], lib->so_name);
    int fd = ld_open(path, O_RDONLY, 0);
    if (fd < 0) {
      LOG(2, "Finding %s: %s failed (can't open)\n", lib->so_name, path);
      continue;
    }

    apos_stat_t stat;
    if (ld_fstat(fd, &stat) != 0) {
      LOG(1, "Unable to stat %s\n", path);
      ld_close(fd);
      continue;
    }

    void* base = 0;
    size_t mapping_size = align_up(stat.st_size, PAGE_SIZE);
    int result = ld_mmap(&base, mapping_size, PROT_READ, MAP_SHARED, fd, 0);
    if (result < 0) {
      LOG(0, "Unable to mmap %s\n", path);
      ld_close(fd);
      continue;
    }

    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)base;
    if (elf64_check_header(ehdr) != 0) {
      LOG(1, "Bad ELF header: %s\n", path);
      ld_munmap((void*)base, mapping_size);
      ld_close(fd);
      continue;
    }

    elf64_phdr_info_t phdrs;
    result = elf64_parse_phdr((uint64_t)base, ehdr, ELF_MAPPED_FILE, &phdrs);
    if (result) {
      LOG(1, "No DYNAMIC section found in %s\n", path);
      ld_munmap((void*)base, mapping_size);
      ld_close(fd);
      continue;
    }
    result = elf64_parse_dynamic((uint64_t)base, ehdr, &phdrs, &lib->dyn);
    if (result) {
      LOG(1, "Unable to parse DYNAMIC section in %s\n", path);
      ld_munmap((void*)base, mapping_size);
      ld_close(fd);
      continue;
    }

    const char* soname = lib->so_name;
    // If the library specifies a different soname, use that instead --- but
    // only if it matches.
    if (lib->dyn.soname) {
      soname = lib->dyn.soname;
      LOG(3, "%s SONAME: %s\n", path, soname);
      if (kstrcmp(soname, lib->so_name) != 0) {
        ld_close(fd);
        ld_munmap((void*)base, mapping_size);
        continue;
      }
    }

    // We found a matching library!  Fill in the appropriate metadata and undo
    // the temporary mapping we set up.
    lib->state = LIB_FOUND;
    char* s2 = ld_alloc(kstrlen(soname) + 1);
    kstrcpy(s2, soname);
    lib->so_name = s2;
    s2 = ld_alloc(kstrlen(path) + 1);
    kstrcpy(s2, path);
    lib->path = s2;
    lib->fd = fd;

    // Note that this will be invalidated once we undo the mapping; we'll have
    // to reparse these later once we actually load the library :/
    lib->ehdr = ehdr;
    return mapping_size;
  }
  return 0;
}

static void add_needed(ctx_t* ctx, const lib_t* lib) {
  const Elf64_Dyn* dyn = lib->dyn.dyn_array;

  for (int i = 0; dyn[i].d_tag != DT_NULL; ++i) {
    if (dyn[i].d_tag == DT_NEEDED) {
      const char* soname = lib->dyn.strtab + dyn[i].d_un.d_val;
      LOG(2, "Needed: %s -> %s\n", lib->path ? lib->path : "<bin>", soname);
      // TODO(aoates): use a hash table for this to avoid linear search.
      const lib_t* new_lib = NULL;
      // Skipping the binary itself, search for a library with that SONAME we
      // may have already found.
      for (new_lib = ctx->libs->next; new_lib != NULL; new_lib = new_lib->next) {
        if (kstrcmp(new_lib->so_name, soname) == 0) {
          LOG(2, "  %s met with existing library %s\n", soname,
              new_lib->path ? new_lib->path : "<not yet identified>");
          break;
        }
      }
      if (!new_lib) {
        lib_t* needed = LD_ALLOC(lib_t);
        kmemset(needed, 0, sizeof(lib_t));
        needed->state = LIB_NEEDED;
        needed->so_name = ld_alloc(kstrlen(soname) + 1);
        kstrcpy((char*)needed->so_name, soname);
        needed->fd = -1;
        ctx->last_lib->next = needed;
        ctx->last_lib = needed;
      }
    }
  }
}

int find_libs(ctx_t* ctx) {
  KASSERT(ctx->libs == ctx->last_lib);
  KASSERT(ctx->last_lib->next == NULL);
  KASSERT(ctx->libs->state == LIB_LOADED);
  KASSERT(ctx->libs->ehdr != NULL);
  KASSERT(ctx->libs->dyn.dyn_array != NULL);

  // Add the root NEEDED entries.
  add_needed(ctx, ctx->libs);

  // Continue until we've resolved everything.
  lib_t* lib = ctx->libs->next;
  int result = 0;
  while (lib) {
    // Look for a lib with the right filename or SONAME.  This creates a
    // temporary mmap of the whole file (which is NOT the same as the final
    // loaded image will be) and returns its length.
    int len = find_lib(lib);
    if (len <= 0) {
      LOG(0, "Unable to find %s\n", lib->so_name);
      result = -1;
      lib = lib->next;
      continue;
    }

    // Find other NEEDED libraries.
    add_needed(ctx, lib);

    // Unmap the current temporary mapping, and continue.
    KASSERT(0 == ld_munmap((void*)lib->ehdr, len));
    lib->ehdr = NULL;
    kmemset(&lib->dyn, 0, sizeof(elf64_dyninfo_t));
    lib = lib->next;
  }
  return result;
}

void load_libs(ctx_t* ctx) {
  KASSERT(ctx->libs->state == LIB_LOADED);

  // Continue until we've loaded everything.
  lib_t* lib = ctx->libs->next;
  while (lib) {
    KASSERT(lib->state == LIB_FOUND);
    KASSERT(lib->bin == NULL);

    int result = elf64_load(lib->fd, &lib->bin);
    if (result) {
      LOG(0, "Error: unable to load %s\n", lib->path);
      ld_exit(1);
    }
    if (lib->bin->num_regions == 0) {
      continue;
    }

    // Pick the next free address to load into.
    // TODO(aoates): consider starting each library at an even power of two that
    // contains the full library image, to make address math easier.
    ctx->next_load_addr = align_up(ctx->next_load_addr, PAGE_SIZE);
    LOG(1, "Loading %s at %p\n", lib->so_name, (void*)ctx->next_load_addr);
    lib->bin->base_addr = ctx->next_load_addr;
    for (int i = 0; i < lib->bin->num_regions; ++i) {
      lib->bin->regions[i].vaddr += lib->bin->base_addr;
    }
    if (lib->bin->entry) {
      lib->bin->entry += lib->bin->base_addr;
    }
    const load_region_t* last_region =
        &lib->bin->regions[lib->bin->num_regions - 1];
    ctx->next_load_addr = last_region->vaddr + last_region->mem_len;

    result = load_map_binary(lib->fd, lib->bin);
    if (result) {
      LOG(0, "Error: unable to load library %s\n", lib->path);
      ld_exit(1);
    }

    // Reparse the dynamic sections from the newly loaded position.
    elf64_phdr_info_t phdrs;
    KASSERT(lib->bin->regions[0].file_offset == 0);
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)lib->bin->regions[0].vaddr;
    KASSERT(0 == elf64_parse_phdr(lib->bin->base_addr, ehdr, ELF_MAPPED_LOADED,
                                  &phdrs));
    KASSERT(0 ==
            elf64_parse_dynamic(lib->bin->base_addr, ehdr, &phdrs, &lib->dyn));

    lib->state = LIB_LOADED;
    lib = lib->next;
  }
}

void relocate_libs(ctx_t* ctx) {
  KASSERT(ctx->libs->state == LIB_LOADED);

  // Relocate all the libraries first, then relocated the executable.  This
  // ensures that any library relocations are completed before any executable
  // COPY relocations.
  lib_t* lib = ctx->libs->next;
  while (lib) {
    elf64_relocate(ctx, lib);
    lib = lib->next;
  }
  elf64_relocate(ctx, ctx->libs);  // Relocate the executable.
}
