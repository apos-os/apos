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
#include "dev/block_dev.h"

// Initialize the ATA driver and scan the primary and secondary channels for ATA
// devices.
//
// REQUIRES: pci_init() -- in case the ATA bus is accessed through a PCI bridge.
void ata_init();

// Returns the number of ATA devices found at initialization time.
int ata_num_devices();

// Returns the block_dev_t corresponding to an ATA device.
block_dev_t* ata_get_block_dev(int dev);

// Sets the base address of the PCI DMA bus master control registers.  Can be
// called before ata_init() --- presumably by the busmaster driver itself.
//
// If this has been called, then the ATA driver will use these port offsets to
// communicate with the busmaster (presumably a PIIX chip) to do DMA.
void ata_enable_bumaster(uint16_t primary_offset, uint16_t secondary_offset);

#endif
