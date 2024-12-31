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

#ifndef APOO_SANITIZERS_TSAN_TSAN_PARAMS_H
#define APOO_SANITIZERS_TSAN_TSAN_PARAMS_H

// Multiplier for thread stack size.
#define TSAN_STACK_MULT 2

// When TSAN is enabled, what portion of pages to allocate to the heap (vs user
// pages and other uses).  The heap plus shadow pages will get <total> /
// TSAN_HEAP_FRACTION pages.
#define TSAN_HEAP_FRACTION 2

// How many shadow cells to track per address.  More shadow cells uses more
// memory but can catch more races.
#define TSAN_SHADOW_CELLS 4

// How many bytes each shadow cell uses.
#define TSAN_SHADOW_CELL_SIZE 8

// How many bytes each shadow cell tracks.
#define TSAN_MEMORY_CELL_SIZE 8

// How many shadow addresses need to be allocated for each TSAN-tracked address.
#define TSAN_SHADOW_MEMORY_MULT TSAN_SHADOW_CELLS

_Static_assert(TSAN_SHADOW_CELLS * TSAN_SHADOW_CELL_SIZE /
                       (double)TSAN_MEMORY_CELL_SIZE ==
                   TSAN_SHADOW_MEMORY_MULT,
               "TSAN parameters incorrect");

// How many thread IDs to track in each vector clock.  This caps the number of
// simultaneous active threads.
#define TSAN_THREAD_SLOTS 64

#endif
