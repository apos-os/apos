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

#include "dev/devicetree/dtb.h"

#include "common/endian.h"
#include "common/errno.h"
#include "common/kstring.h"

int dtfdt_validate(const void* buf, fdt_header_t* header) {
  const fdt_header_t_bige* hdr_in = buf;
  if (btoh32(hdr_in->magic) != 0xd00dfeed) {
    return -EINVAL;
  }
  kmemcpy(header, buf, sizeof(fdt_header_t));
  header->magic = btoh32(header->magic);
  header->totalsize = btoh32(header->totalsize);
  header->off_dt_struct = btoh32(header->off_dt_struct);
  header->off_dt_strings = btoh32(header->off_dt_strings);
  header->off_mem_rsvmap = btoh32(header->off_mem_rsvmap);
  header->version = btoh32(header->version);
  header->last_comp_version = btoh32(header->last_comp_version);
  header->boot_cpuid_phys = btoh32(header->boot_cpuid_phys);
  header->size_dt_strings = btoh32(header->size_dt_strings);
  header->size_dt_struct = btoh32(header->size_dt_struct);

  if (header->last_comp_version > DTFDT_VERSION) {
    return -EINVAL;
  }

  return 0;
}
