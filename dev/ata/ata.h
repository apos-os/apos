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

// ATA driver.
#ifndef APOO_DEV_ATA_H
#define APOO_DEV_ATA_H

#include <stdint.h>

// Contains data about the port offsets for the primary and secondary ATA
// channels.
struct ata_channel {
  uint16_t cmd_offset;  // Port offset for the command block.
  uint16_t ctrl_offset;  // Port offset for the control block.
  uint8_t irq;  // The IRQ used by this channel.
};
typedef struct ata_channel ata_channel_t;

struct ata {
  ata_channel_t primary;
  ata_channel_t secondary;
};
typedef struct ata ata_t;

// Initialize the ATA driver with the given channel information.  For instance,
// the PCI/IDE bridge chip driver might call this after it has initialized the
// bridge.
void ata_init(const ata_t* ata);

#endif
