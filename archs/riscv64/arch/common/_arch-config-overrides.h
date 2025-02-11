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

#ifndef APOO_ARCHS_RISCV64_ARCH_COMMON__ARCH_CONFIG_OVERRIDES_H
#define APOO_ARCHS_RISCV64_ARCH_COMMON__ARCH_CONFIG_OVERRIDES_H

#include "common/config.h"

#undef ARCH_SUPPORTS_RAW_VGA
#define ARCH_SUPPORTS_RAW_VGA 0

#undef ARCH_SUPPORTS_LEGACY_PC_DEVS
#define ARCH_SUPPORTS_LEGACY_PC_DEVS 0
#undef ARCH_SUPPORTS_IOPORT
#define ARCH_SUPPORTS_IOPORT 0

// TODO(tsan): enable user-mode tests
#if ENABLE_TSAN
#undef ARCH_RUN_USER_TESTS
#define ARCH_RUN_USER_TESTS 0
#endif

#endif
