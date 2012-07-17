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

#endif
