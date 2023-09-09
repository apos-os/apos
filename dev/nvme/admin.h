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

// Helpers for admin queue operations.
#ifndef APOO_DEV_NVME_ADMIN_H
#define APOO_DEV_NVME_ADMIN_H

#include <stdint.h>

// Parsed result of an admin Identify Controller command.
typedef struct {
  uint16_t pci_vendor_id;
  uint16_t pci_subsys_vendor_id;
  char serial[21];
  char model[41];
  char firmware_rev[9];
  uint8_t mdts;
  uint16_t ctrl_id;
  uint8_t ctrl_type;
  int sqes_max_bytes;
  int sqes_min_bytes;
  int cqes_max_bytes;
  int cqes_min_bytes;
  uint16_t max_cmd;
} nvme_admin_identify_ctrl_t;

// Parses an Identify Controller response (4096 bytes).
void nvme_admin_parse_identify_ctrl(const void* buf,
                                    nvme_admin_identify_ctrl_t* resp);

#endif
