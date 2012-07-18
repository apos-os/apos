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

// A set of generic tests that can be run against any block device.
#ifndef APOO_TEST_BLOCKDEV_TEST_H
#define APOO_TEST_BLOCKDEV_TEST_H

// Repeatedly read and write blocks of various lengths and sizes (some
// overlapping) and verify that everything comes back correctly.
void bd_standard_test(block_dev_t* bd);

// Takes an array of block devices, and spawns a bunch of threads that
// simultaneously read and write interleaving blocks on multiple devices.
//
// This tests things liike channel locking for ATA, where multiple block devices
// can't be used simultaneously.
//
// num_threads is the number of threads (per block device) to spawn; num_blocks
// is the number of blocks (striped across the block device) that each thread
// should write.  num_threads * num_blocks must be <= the size of each block
// device.
void bd_thread_test(block_dev_t** bds, int len,
                    uint32_t num_threads, uint32_t num_blocks);

#endif
