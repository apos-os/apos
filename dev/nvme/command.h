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

#ifndef APOO_DEV_NVME_COMMAND_H
#define APOO_DEV_NVME_COMMAND_H

#include <stdint.h>

typedef struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint32_t opcode : 8, fuse : 2, _reserved1 : 4, psdt : 2, cmd_id : 16;
#else
  uint32_t cmd_id : 16, psdt : 2, _reserved1 : 4, fuse : 2, opcode : 8;
#endif
  uint32_t nsid;  // Namespace identifier
  uint32_t cdw2;  // Command DWORD 2
  uint32_t cdw3;  // Command DWORD 3
  uint64_t mptr;  // Metadata pointer
  uint64_t dptr[2];  // Data pointer
  uint32_t cdw10;  // NDT for admin commands
  uint32_t cdw11;  // NDM for admin commands
  uint32_t cdw12;
  uint32_t cdw13;
  uint32_t cdw14;
  uint32_t cdw15;
} nvme_cmd_t;
_Static_assert(sizeof(nvme_cmd_t) == 64, "Bad nvme_cmd_t");

typedef struct {
  uint32_t dw0;
  uint32_t dw1;
  uint16_t sq_headptr;
  uint16_t sq_id;
  uint16_t cmd_id;
  uint16_t status_phase;
} nvme_completion_t;
_Static_assert(sizeof(nvme_completion_t) == 16, "Bad nvme_completion_t");

#endif
