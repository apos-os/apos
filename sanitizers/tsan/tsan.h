// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SANITIZERS_TSAN_TSAN_H
#define APOO_SANITIZERS_TSAN_TSAN_H

#include "sanitizers/tsan/report.h"

// Initialize the TSAN data structures.  Should be called early in the boot
// process but after kmalloc_init().
void tsan_init(void);

typedef void (*tsan_report_fn_t)(const tsan_report_t*);

// Set the function to call when a race is detected, or NULL to restore the
// default (which panics).  Note that the function may be called from an
// interrupt context.
void tsan_set_report_func(tsan_report_fn_t fn);

#endif
