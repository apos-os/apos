// Copyright 2015 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_ARCHS_COMMON_ARCH_PROC_EXEC_H
#define APOO_ARCHS_COMMON_ARCH_PROC_EXEC_H

#include <stdbool.h>

#include "proc/load/load.h"
#include "arch/proc/user_context.h"

// Returns true if the current architecture can run the given binary.
bool arch_binary_supported(const load_binary_t* bin);

// Prepare to run a usermode binary (by creating the stack, preparing the
// arguments, etc), and populate |ctx| with the context to be applied when the
// binary is run.
//
// Returns -error on failure.
int arch_prep_exec(const load_binary_t* bin, char* const argv[],
                   char* const envp[], user_context_t* ctx);

#endif
