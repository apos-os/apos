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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"

// Special stack for double faults.
#define DBLFAULT_STACK_SIZE 4096
uint8_t g_dblfault_stack[DBLFAULT_STACK_SIZE] __attribute__((aligned(16)));

void rsv_dblfault_handler(uint64_t interrupted_addr, uint64_t interrupted_sp) {
  klogfm(KL_GENERAL, FATAL, "Kernel double fault at %#lx\n", interrupted_addr);
}
