// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_DEV_DEVICETREE_DTB_H
#define APOO_DEV_DEVICETREE_DTB_H

#include <stdint.h>

#define DTFDT_VERSION 17

// Header of a DTB blob.
typedef struct {
  uint32_t magic;
  uint32_t totalsize;
  uint32_t off_dt_struct;
  uint32_t off_dt_strings;
  uint32_t off_mem_rsvmap;
  uint32_t version;
  uint32_t last_comp_version;
  uint32_t boot_cpuid_phys;
  uint32_t size_dt_strings;
  uint32_t size_dt_struct;
} __attribute__((packed)) fdt_header_t;

typedef fdt_header_t fdt_header_t_bige;

// Reads the header at the given address and does basic validation.  If OK,
// returns zero and copies the header data (in host endian) into the given
// header struct.
int dtfdt_validate(const void* buf, fdt_header_t* header);

#endif
