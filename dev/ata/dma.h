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

// Functions for DMA access to ATA drives and the DMA busmaster.
#ifndef APOO_DEV_ATA_DMA_H
#define APOO_DEV_ATA_DMA_H

// Initialize the DMA subsytem that talks to the PIIX(3) controller.
void dma_init();

// Returns the buffer used for DMA.  It is exactly one page long.
//
// NOTE: you MUST have the buffer locked (dma_lock_buffer()/dma_unlock_buffer())
// before reading or writing to the buffer.  This includes by invoking the DMA
// functions below.
void* dma_get_buffer();

// Returns the size of the buffer, in bytes.
uint32_t dma_buffer_size();

// Lock and unlock the DMA buffer.
void dma_lock_buffer();
void dma_unlock_buffer();

// Initiate a DMA transfer on the currently-selected drive on the given channel.
// This is step 1, which sets up and loads the PRDT in the controller, and sets
// the status bits correctly.  If the transfer is a write, the caller should
// have already copied the data into the dma_get_buffer() region.
//
// After calling this, the DMA transfer command must be given to the device, and
// then dma_start_transfer() should be called.
void dma_setup_transfer(ata_channel_t* channel, uint32_t len, uint8_t is_write);

// Step 2 of a DMA.  This actually starts the DMA process in the controller.
// dma_setup_transfer() must have been called already, and the DMA command
// should have already been sent to the device.
void dma_start_transfer(ata_channel_t* channel);

// Finish a DMA transfer.  Called after the transfer has completed (fully or
// with an error) to reset the DMA.
void dma_finish_transfer(ata_channel_t* channel);

#endif
