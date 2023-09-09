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
#include "dev/nvme/admin.h"

#include "common/endian.h"
#include "common/kstring.h"

void nvme_admin_parse_identify_ctrl(const void* buf,
                                    nvme_admin_identify_ctrl_t* resp) {
  resp->pci_vendor_id = ltoh16(*(const uint16_t*)buf);
  resp->pci_subsys_vendor_id = ltoh16(*(const uint16_t*)(buf + 2));
  kmemcpy(&resp->serial, buf + 4, 20);
  resp->serial[20] = '\0';
  kmemcpy(&resp->model, buf + 24, 40);
  resp->model[40] = '\0';
  kmemcpy(&resp->firmware_rev, buf + 64, 8);
  resp->firmware_rev[8] = '\0';
  resp->mdts = *(const uint8_t*)(buf + 77);
  resp->ctrl_id = ltoh16(*(const uint16_t*)(buf + 78));
  resp->ctrl_type = *(const uint8_t*)(buf + 111);

  uint8_t sqes = *(const uint8_t*)(buf + 512);
  resp->sqes_min_bytes = 1 << (sqes & 0x0f);
  resp->sqes_max_bytes = 1 << (sqes >> 4);

  uint8_t cqes = *(const uint8_t*)(buf + 513);
  resp->cqes_min_bytes = 1 << (cqes & 0x0f);
  resp->cqes_max_bytes = 1 << (cqes >> 4);

  resp->max_cmd = ltoh16(*(const uint16_t*)(buf + 514));
}
