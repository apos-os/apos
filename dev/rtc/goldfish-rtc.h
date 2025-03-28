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

// Very basic driver for the Google goldfish RTC.
#ifndef APOO_DEV_RTC_GOLDFISH_RTC_H
#define APOO_DEV_RTC_GOLDFISH_RTC_H

#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/drivers.h"
#include "user/include/apos/time_types.h"

// Driver loader.
int goldfish_rtc_driver(const dt_tree_t* tree, const dt_node_t* node,
                        const char* node_path, dt_driver_info_t* driver);

// Read the current time from a Goldfish RTC if present.
int goldfish_rtc_read(struct apos_timespec* ts);

#endif
